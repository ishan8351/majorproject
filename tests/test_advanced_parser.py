import tempfile
from pathlib import Path
import pytest

from regradar.parser.hcl_parser import HCLParser
from regradar.parser.reference_extractor import ReferenceExtractor
from regradar.parser.module_resolver import ModuleResolver, sanitize_identifier
from regradar.graph.builder import DependencyGraphBuilder
from regradar.graph.centrality import CentralityEngine
from regradar.models import RiskTier


def test_sanitize_identifier():
    assert sanitize_identifier('"aws_instance"') == "aws_instance"
    assert sanitize_identifier("'web'") == "web"
    assert sanitize_identifier('""double_quoted""') == "double_quoted"
    assert sanitize_identifier("   clean   ") == "clean"
    assert sanitize_identifier(None) == ""


def test_data_source_parsing_and_dependency():
    hcl_content = """
    data "aws_ami" "ubuntu" {
      most_recent = true
      owners      = ["099720109477"]
    }

    resource "aws_instance" "web" {
      ami           = data.aws_ami.ubuntu.id
      instance_type = "t3.micro"
    }
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        tf_file = Path(tmp_dir) / "main.tf"
        tf_file.write_text(hcl_content)

        parser = HCLParser()
        resources = parser.parse_file(tf_file)

        assert "data.aws_ami.ubuntu" in resources
        assert "aws_instance.web" in resources

        data_res = resources["data.aws_ami.ubuntu"]
        assert data_res.id == "data.aws_ami.ubuntu"
        assert data_res.resource_type == "data.aws_ami"
        assert data_res.name == "ubuntu"

        web_res = resources["aws_instance.web"]
        assert "data.aws_ami.ubuntu" in web_res.inferred_dependencies

        builder = DependencyGraphBuilder(resources)
        assert builder.is_dag is True
        assert builder.graph.has_edge("data.aws_ami.ubuntu", "aws_instance.web")
        assert builder.get_blast_radius("data.aws_ami.ubuntu") == {"aws_instance.web"}


def test_multiple_data_sources_with_cross_linking():
    hcl_content = """
    data "aws_vpc" "default" {
      default = true
    }

    data "aws_subnet" "primary" {
      vpc_id = data.aws_vpc.default.id
    }

    resource "aws_security_group" "sg" {
      name   = "allow_tls"
      vpc_id = data.aws_vpc.default.id
    }

    resource "aws_instance" "app" {
      ami                    = "ami-0c55b159cbfafe1f0"
      subnet_id              = data.aws_subnet.primary.id
      vpc_security_group_ids = [aws_security_group.sg.id]
    }
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        tf_file = Path(tmp_dir) / "main.tf"
        tf_file.write_text(hcl_content)

        parser = HCLParser()
        resources = parser.parse_file(tf_file)

        assert len(resources) == 4
        assert "data.aws_vpc.default" in resources
        assert "data.aws_subnet.primary" in resources
        assert "aws_security_group.sg" in resources
        assert "aws_instance.app" in resources

        # Verify cross links
        subnet = resources["data.aws_subnet.primary"]
        assert "data.aws_vpc.default" in subnet.inferred_dependencies

        sg = resources["aws_security_group.sg"]
        assert "data.aws_vpc.default" in sg.inferred_dependencies

        app = resources["aws_instance.app"]
        assert "data.aws_subnet.primary" in app.inferred_dependencies
        assert "aws_security_group.sg" in app.inferred_dependencies

        builder = DependencyGraphBuilder(resources)
        assert builder.is_dag is True

        blast_radius = builder.get_blast_radius("data.aws_vpc.default")
        assert "data.aws_subnet.primary" in blast_radius
        assert "aws_security_group.sg" in blast_radius
        assert "aws_instance.app" in blast_radius


def test_local_child_module_resolution():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        mod_dir = root / "modules" / "vpc"
        mod_dir.mkdir(parents=True)

        # Child module files
        (mod_dir / "variables.tf").write_text("""
        variable "cidr" {
          type    = string
          default = "10.0.0.0/16"
        }
        """)

        (mod_dir / "main.tf").write_text("""
        resource "aws_vpc" "mod_vpc" {
          cidr_block = var.cidr
        }

        resource "aws_subnet" "public" {
          vpc_id     = aws_vpc.mod_vpc.id
          cidr_block = "10.0.1.0/24"
        }
        """)

        (mod_dir / "outputs.tf").write_text("""
        output "subnet_id" {
          value = aws_subnet.public.id
        }

        output "vpc_id" {
          value = aws_vpc.mod_vpc.id
        }
        """)

        # Root file
        (root / "main.tf").write_text("""
        module "vpc" {
          source = "./modules/vpc"
          cidr   = "10.200.0.0/16"
        }

        resource "aws_instance" "web" {
          ami       = "ami-12345"
          subnet_id = module.vpc.subnet_id
        }
        """)

        parser = HCLParser()
        resources = parser.parse_directory(root)

        expected_ids = {
            "module.vpc.aws_vpc.mod_vpc",
            "module.vpc.aws_subnet.public",
            "aws_instance.web",
        }
        assert set(resources.keys()) == expected_ids

        # Child subnet references child VPC
        child_subnet = resources["module.vpc.aws_subnet.public"]
        assert "module.vpc.aws_vpc.mod_vpc" in child_subnet.inferred_dependencies

        # Parent web instance references child subnet through module output
        web_instance = resources["aws_instance.web"]
        assert "module.vpc.aws_subnet.public" in web_instance.inferred_dependencies

        # Build graph and check blast radius
        builder = DependencyGraphBuilder(resources)
        assert builder.is_dag is True
        assert builder.graph.has_edge("module.vpc.aws_vpc.mod_vpc", "module.vpc.aws_subnet.public")
        assert builder.graph.has_edge("module.vpc.aws_subnet.public", "aws_instance.web")

        blast = builder.get_blast_radius("module.vpc.aws_vpc.mod_vpc")
        assert blast == {"module.vpc.aws_subnet.public", "aws_instance.web"}


def test_recursive_nested_module_resolution():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        tier1_dir = root / "modules" / "network"
        tier2_dir = tier1_dir / "subnets"
        tier2_dir.mkdir(parents=True)

        # Tier 2 module
        (tier2_dir / "main.tf").write_text("""
        resource "aws_subnet" "db_subnet" {
          cidr_block = "10.0.2.0/24"
        }

        output "subnet_id" {
          value = aws_subnet.db_subnet.id
        }
        """)

        # Tier 1 module
        (tier1_dir / "main.tf").write_text("""
        resource "aws_vpc" "net_vpc" {
          cidr_block = "10.0.0.0/16"
        }

        module "subnets" {
          source = "./subnets"
        }

        output "vpc_id" {
          value = aws_vpc.net_vpc.id
        }

        output "db_subnet_id" {
          value = module.subnets.subnet_id
        }
        """)

        # Root module
        (root / "main.tf").write_text("""
        module "network" {
          source = "./modules/network"
        }

        resource "aws_db_instance" "db" {
          subnet_id = module.network.db_subnet_id
        }
        """)

        parser = HCLParser()
        resources = parser.parse_directory(root)

        expected_ids = {
            "module.network.aws_vpc.net_vpc",
            "module.network.module.subnets.aws_subnet.db_subnet",
            "aws_db_instance.db",
        }
        assert set(resources.keys()) == expected_ids

        db = resources["aws_db_instance.db"]
        assert "module.network.module.subnets.aws_subnet.db_subnet" in db.inferred_dependencies

        builder = DependencyGraphBuilder(resources)
        assert builder.is_dag is True
        assert builder.graph.has_edge(
            "module.network.module.subnets.aws_subnet.db_subnet", "aws_db_instance.db"
        )


def test_module_input_variable_dependency_propagation():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        mod_dir = root / "modules" / "compute"
        mod_dir.mkdir(parents=True)

        (mod_dir / "main.tf").write_text("""
        variable "vpc_id" {
          type = string
        }

        resource "aws_security_group" "mod_sg" {
          vpc_id = var.vpc_id
        }
        """)

        (root / "main.tf").write_text("""
        resource "aws_vpc" "root_vpc" {
          cidr_block = "10.0.0.0/16"
        }

        module "compute" {
          source = "./modules/compute"
          vpc_id = aws_vpc.root_vpc.id
        }
        """)

        parser = HCLParser()
        resources = parser.parse_directory(root)

        assert "aws_vpc.root_vpc" in resources
        assert "module.compute.aws_security_group.mod_sg" in resources

        sg = resources["module.compute.aws_security_group.mod_sg"]
        assert "aws_vpc.root_vpc" in sg.inferred_dependencies

        builder = DependencyGraphBuilder(resources)
        assert builder.is_dag is True
        assert builder.graph.has_edge("aws_vpc.root_vpc", "module.compute.aws_security_group.mod_sg")


def test_module_explicit_depends_on():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        mod_dir = root / "modules" / "storage"
        mod_dir.mkdir(parents=True)

        (mod_dir / "main.tf").write_text("""
        resource "aws_s3_bucket" "b1" {
          bucket = "bucket-1"
        }
        """)

        (root / "main.tf").write_text("""
        module "storage" {
          source = "./modules/storage"
        }

        resource "aws_instance" "app" {
          ami        = "ami-1111"
          depends_on = [module.storage]
        }
        """)

        parser = HCLParser()
        resources = parser.parse_directory(root)

        app = resources["aws_instance.app"]
        assert "module.storage.aws_s3_bucket.b1" in app.explicit_dependencies

        builder = DependencyGraphBuilder(resources)
        assert builder.is_dag is True
        assert builder.graph.has_edge("module.storage.aws_s3_bucket.b1", "aws_instance.app")


def test_multi_cloud_azure_schema():
    hcl_content = """
    resource "azurerm_resource_group" "rg" {
      name     = "rg-prod"
      location = "eastus"
    }

    resource "azurerm_virtual_network" "vnet" {
      name                = "vnet-prod"
      resource_group_name = azurerm_resource_group.rg.name
      address_space       = ["10.0.0.0/16"]
    }

    resource "azurerm_subnet" "subnet" {
      name                 = "snet-prod"
      resource_group_name  = azurerm_resource_group.rg.name
      virtual_network_name = azurerm_virtual_network.vnet.name
      address_prefixes     = ["10.0.1.0/24"]
    }

    resource "azurerm_network_security_group" "nsg" {
      name                = "nsg-prod"
      resource_group_name = azurerm_resource_group.rg.name
    }

    resource "azurerm_subnet_network_security_group_association" "assoc" {
      subnet_id                 = azurerm_subnet.subnet.id
      network_security_group_id = azurerm_network_security_group.nsg.id
    }
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        tf_file = Path(tmp_dir) / "main.tf"
        tf_file.write_text(hcl_content)

        parser = HCLParser()
        resources = parser.parse_file(tf_file)

        assert len(resources) == 5
        assert HCLParser.detect_provider("azurerm_virtual_network") == "azurerm"
        assert HCLParser.detect_provider("azurerm_resource_group") == "azurerm"

        vnet = resources["azurerm_virtual_network.vnet"]
        assert "azurerm_resource_group.rg" in vnet.inferred_dependencies

        subnet = resources["azurerm_subnet.subnet"]
        assert "azurerm_resource_group.rg" in subnet.inferred_dependencies
        assert "azurerm_virtual_network.vnet" in subnet.inferred_dependencies

        assoc = resources["azurerm_subnet_network_security_group_association.assoc"]
        assert "azurerm_subnet.subnet" in assoc.inferred_dependencies
        assert "azurerm_network_security_group.nsg" in assoc.inferred_dependencies

        builder = DependencyGraphBuilder(resources)
        assert builder.is_dag is True

        engine = CentralityEngine(builder.graph)
        summary = engine.get_summary()

        rg_metrics = summary.metrics["azurerm_resource_group.rg"]
        assert rg_metrics.risk_tier == RiskTier.CRITICAL_ROOT
        assert rg_metrics.descendant_count == 4

        assoc_metrics = summary.metrics["azurerm_subnet_network_security_group_association.assoc"]
        assert assoc_metrics.auto_remediate is True
        assert assoc_metrics.descendant_count == 0


def test_multi_cloud_gcp_schema():
    hcl_content = """
    resource "google_compute_network" "vpc_network" {
      name                    = "custom-vpc"
      auto_create_subnetworks = false
    }

    resource "google_compute_subnetwork" "subnet" {
      name          = "custom-subnet"
      ip_cidr_range = "10.0.1.0/24"
      network       = google_compute_network.vpc_network.id
    }

    resource "google_compute_firewall" "allow_ssh" {
      name    = "allow-ssh"
      network = google_compute_network.vpc_network.name
    }

    resource "google_compute_instance" "vm" {
      name         = "app-instance"
      machine_type = "e2-medium"
      network_interface {
        subnetwork = google_compute_subnetwork.subnet.id
      }
    }
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        tf_file = Path(tmp_dir) / "main.tf"
        tf_file.write_text(hcl_content)

        parser = HCLParser()
        resources = parser.parse_file(tf_file)

        assert len(resources) == 4
        assert HCLParser.detect_provider("google_compute_network") == "google"
        assert HCLParser.detect_provider("google_compute_instance") == "google"

        subnet = resources["google_compute_subnetwork.subnet"]
        assert "google_compute_network.vpc_network" in subnet.inferred_dependencies

        firewall = resources["google_compute_firewall.allow_ssh"]
        assert "google_compute_network.vpc_network" in firewall.inferred_dependencies

        vm = resources["google_compute_instance.vm"]
        assert "google_compute_subnetwork.subnet" in vm.inferred_dependencies

        builder = DependencyGraphBuilder(resources)
        assert builder.is_dag is True

        engine = CentralityEngine(builder.graph)
        summary = engine.get_summary()

        vpc_metrics = summary.metrics["google_compute_network.vpc_network"]
        assert vpc_metrics.risk_tier == RiskTier.CRITICAL_ROOT
        assert vpc_metrics.descendant_count == 3


def test_multi_cloud_kubernetes_schema():
    hcl_content = """
    resource "kubernetes_namespace" "prod" {
      metadata {
        name = "prod-env"
      }
    }

    resource "kubernetes_config_map" "config" {
      metadata {
        name      = "app-config"
        namespace = kubernetes_namespace.prod.metadata[0].name
      }
    }

    resource "kubernetes_deployment" "app" {
      metadata {
        name      = "frontend"
        namespace = kubernetes_namespace.prod.metadata[0].name
      }
    }
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        tf_file = Path(tmp_dir) / "main.tf"
        tf_file.write_text(hcl_content)

        parser = HCLParser()
        resources = parser.parse_file(tf_file)

        assert len(resources) == 3
        assert HCLParser.detect_provider("kubernetes_deployment") == "kubernetes"

        builder = DependencyGraphBuilder(resources)
        assert builder.is_dag is True
        assert builder.graph.has_edge("kubernetes_namespace.prod", "kubernetes_config_map.config")
        assert builder.graph.has_edge("kubernetes_namespace.prod", "kubernetes_deployment.app")


def test_deep_attribute_and_complex_expressions():
    exprs = [
        ("${module.vpc.subnet_id}", {"module.vpc.subnet_id", "module.vpc"}),
        ("data.aws_ami.ubuntu.id", {"data.aws_ami.ubuntu"}),
        ("element(aws_subnet.public.*.id, 0)", {"aws_subnet.public"}),
        ("var.enabled ? aws_vpc.main.id : aws_vpc.backup.id", {"aws_vpc.main", "aws_vpc.backup"}),
        ("aws_subnet.public[0].id", {"aws_subnet.public"}),
        ("kubernetes_service.svc.spec[0].cluster_ip", {"kubernetes_service.svc"}),
        ("module.net.module.sub.aws_subnet.public.id", {"module.net.module.sub.aws_subnet.public", "module.net.module.sub"}),
    ]

    for expr, expected_subset in exprs:
        refs = ReferenceExtractor.extract_from_value(expr)
        for expected in expected_subset:
            assert expected in refs, f"Expected {expected} in {refs} for {expr}"


def test_missing_local_module_dir():
    hcl_content = """
    module "missing" {
      source = "./does_not_exist"
    }

    resource "aws_vpc" "main" {
      cidr_block = "10.0.0.0/16"
    }
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        tf_file = Path(tmp_dir) / "main.tf"
        tf_file.write_text(hcl_content)

        parser = HCLParser()
        # Should not crash on missing local module directory
        resources = parser.parse_file(tf_file)
        assert "aws_vpc.main" in resources

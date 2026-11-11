terraform {
  required_version = ">= 1.0"
}

# --- E-Commerce GDPR Azure Multi-Tier Architecture ---

# 1. Azure Resource Group Foundation
resource "azurerm_resource_group" "rg_gdpr" {
  name     = "rg-ecommerce-prod-europe"
  location = "westeurope"

  tags = {
    Environment = "production"
    Compliance  = "GDPR"
  }
}

# 2. Azure Virtual Network Foundation
resource "azurerm_virtual_network" "vnet_gdpr" {
  name                = "vnet-ecommerce-prod"
  resource_group_name = azurerm_resource_group.rg_gdpr.name
  location            = azurerm_resource_group.rg_gdpr.location
  address_space       = ["10.40.0.0/16"]

  tags = {
    Environment = "production"
  }
}

resource "azurerm_subnet" "subnet_web" {
  name                 = "subnet-web-europe"
  resource_group_name  = azurerm_resource_group.rg_gdpr.name
  virtual_network_name = azurerm_virtual_network.vnet_gdpr.name
  address_prefixes     = ["10.40.1.0/24"]
}

# 3. Perimeter Network Security Group
# Statutory Smell: Inbound SSH Port 22 Open to Internet (CKV_AZURE_9)
resource "azurerm_network_security_group" "nsg_web" {
  name                = "nsg-web-inbound"
  resource_group_name = azurerm_resource_group.rg_gdpr.name
  location            = azurerm_resource_group.rg_gdpr.location

  security_rule {
    name                       = "allow-ssh-internet"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-https"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = {
    Environment = "production"
  }
}

# 4. Azure Storage Account
# Statutory Smells:
#   - HTTP Allowed / Secure Transfer Disabled (CKV_AZURE_3)
#   - Public Blob Access Enabled (CKV_AZURE_33)
#   - Insecure TLS < 1.2 (CKV_AZURE_44)
resource "azurerm_storage_account" "sa_customer_data" {
  name                             = "ecommercedatastore2026"
  resource_group_name              = azurerm_resource_group.rg_gdpr.name
  location                         = azurerm_resource_group.rg_gdpr.location
  account_tier                     = "Standard"
  account_replication_type         = "GRS"
  enable_https_traffic_only        = false
  allow_nested_items_to_be_public  = true
  min_tls_version                  = "TLS1_0"

  tags = {
    Compliance = "GDPR Art. 32"
    DataType   = "EU-Customer-PII"
  }
}

# 5. Azure Blob Container
# Statutory Smell: Public anonymous access enabled on container (CKV_AZURE_33)
resource "azurerm_storage_container" "gdpr_blobs" {
  name                  = "user-profile-data"
  storage_account_name  = azurerm_storage_account.sa_customer_data.name
  container_access_type = "blob"
}

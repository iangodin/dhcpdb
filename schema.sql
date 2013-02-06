
CREATE TABLE dhcp_lease (
	ip_addr INT UNSIGNED NOT NULL,
	mac_addr BINARY(6) NOT NULL,
	expiration DATETIME NOT NULL,

	PRIMARY KEY(ip_addr)
);

CREATE TABLE dhcp_options (
	id BIGINT UNSIGNED NOT NULL,
	ip_addr_from INT UNSIGNED NOT NULL,
	ip_addr_to INT UNSIGNED NOT NULL,
	options VARBINARY(64) NOT NULL,

	PRIMARY KEY(id)
);

CREATE TABLE dhcp_host (
	ip_addr INT UNSIGNED NOT NULL,
	mac_addr BINARY(6) NOT NULL,

	PRIMARY KEY(ip_addr) 
);


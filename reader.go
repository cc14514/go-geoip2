package geoip2

import (
	"fmt"
	"github.com/cc14514/go-geoip2/driver"
	"net"
	"net/http"
)

// The City struct corresponds to the data in the GeoIP2/GeoLite2 City
// databases.
type City struct {
	City struct {
		GeoNameID uint              `driver:"geoname_id"`
		Names     map[string]string `driver:"names"`
	} `driver:"city"`
	Continent struct {
		Code      string            `driver:"code"`
		GeoNameID uint              `driver:"geoname_id"`
		Names     map[string]string `driver:"names"`
	} `driver:"continent"`
	Country struct {
		GeoNameID         uint              `driver:"geoname_id"`
		IsInEuropeanUnion bool              `driver:"is_in_european_union"`
		IsoCode           string            `driver:"iso_code"`
		Names             map[string]string `driver:"names"`
	} `driver:"country"`
	Location struct {
		AccuracyRadius uint16  `driver:"accuracy_radius"`
		Latitude       float64 `driver:"latitude"`
		Longitude      float64 `driver:"longitude"`
		MetroCode      uint    `driver:"metro_code"`
		TimeZone       string  `driver:"time_zone"`
	} `driver:"location"`
	Postal struct {
		Code string `driver:"code"`
	} `driver:"postal"`
	RegisteredCountry struct {
		GeoNameID         uint              `driver:"geoname_id"`
		IsInEuropeanUnion bool              `driver:"is_in_european_union"`
		IsoCode           string            `driver:"iso_code"`
		Names             map[string]string `driver:"names"`
	} `driver:"registered_country"`
	RepresentedCountry struct {
		GeoNameID         uint              `driver:"geoname_id"`
		IsInEuropeanUnion bool              `driver:"is_in_european_union"`
		IsoCode           string            `driver:"iso_code"`
		Names             map[string]string `driver:"names"`
		Type              string            `driver:"type"`
	} `driver:"represented_country"`
	Subdivisions []struct {
		GeoNameID uint              `driver:"geoname_id"`
		IsoCode   string            `driver:"iso_code"`
		Names     map[string]string `driver:"names"`
	} `driver:"subdivisions"`
	Traits struct {
		IsAnonymousProxy    bool `driver:"is_anonymous_proxy"`
		IsSatelliteProvider bool `driver:"is_satellite_provider"`
	} `driver:"traits"`
}

// The Country struct corresponds to the data in the GeoIP2/GeoLite2
// Country databases.
type Country struct {
	Continent struct {
		Code      string            `driver:"code"`
		GeoNameID uint              `driver:"geoname_id"`
		Names     map[string]string `driver:"names"`
	} `driver:"continent"`
	Country struct {
		GeoNameID         uint              `driver:"geoname_id"`
		IsInEuropeanUnion bool              `driver:"is_in_european_union"`
		IsoCode           string            `driver:"iso_code"`
		Names             map[string]string `driver:"names"`
	} `driver:"country"`
	RegisteredCountry struct {
		GeoNameID         uint              `driver:"geoname_id"`
		IsInEuropeanUnion bool              `driver:"is_in_european_union"`
		IsoCode           string            `driver:"iso_code"`
		Names             map[string]string `driver:"names"`
	} `driver:"registered_country"`
	RepresentedCountry struct {
		GeoNameID         uint              `driver:"geoname_id"`
		IsInEuropeanUnion bool              `driver:"is_in_european_union"`
		IsoCode           string            `driver:"iso_code"`
		Names             map[string]string `driver:"names"`
		Type              string            `driver:"type"`
	} `driver:"represented_country"`
	Traits struct {
		IsAnonymousProxy    bool `driver:"is_anonymous_proxy"`
		IsSatelliteProvider bool `driver:"is_satellite_provider"`
	} `driver:"traits"`
}

// The AnonymousIP struct corresponds to the data in the GeoIP2
// Anonymous IP database.
type AnonymousIP struct {
	IsAnonymous       bool `driver:"is_anonymous"`
	IsAnonymousVPN    bool `driver:"is_anonymous_vpn"`
	IsHostingProvider bool `driver:"is_hosting_provider"`
	IsPublicProxy     bool `driver:"is_public_proxy"`
	IsTorExitNode     bool `driver:"is_tor_exit_node"`
}

// The ASN struct corresponds to the data in the GeoLite2 ASN database.
type ASN struct {
	AutonomousSystemNumber       uint   `driver:"autonomous_system_number"`
	AutonomousSystemOrganization string `driver:"autonomous_system_organization"`
}

// The ConnectionType struct corresponds to the data in the GeoIP2
// Connection-Type database.
type ConnectionType struct {
	ConnectionType string `driver:"connection_type"`
}

// The Domain struct corresponds to the data in the GeoIP2 Domain database.
type Domain struct {
	Domain string `driver:"domain"`
}

// The ISP struct corresponds to the data in the GeoIP2 ISP database.
type ISP struct {
	AutonomousSystemNumber       uint   `driver:"autonomous_system_number"`
	AutonomousSystemOrganization string `driver:"autonomous_system_organization"`
	ISP                          string `driver:"isp"`
	Organization                 string `driver:"organization"`
}

type databaseType int

const (
	isAnonymousIP = 1 << iota
	isASN
	isCity
	isConnectionType
	isCountry
	isDomain
	isEnterprise
	isISP
)

// DBReader holds the driver.DBReader struct. It can be created using the
// Open and FromBytes functions.
type DBReader struct {
	mmdbDBReader *driver.Reader
	databaseType databaseType
}

// InvalidMethodError is returned when a lookup method is called on a
// database that it does not support. For instance, calling the ISP method
// on a City database.
type InvalidMethodError struct {
	Method       string
	DatabaseType string
}

func (e InvalidMethodError) Error() string {
	return fmt.Sprintf(`geoip2: the %s method does not support the %s database`,
		e.Method, e.DatabaseType)
}

// UnknownDatabaseTypeError is returned when an unknown database type is
// opened.
type UnknownDatabaseTypeError struct {
	DatabaseType string
}

func (e UnknownDatabaseTypeError) Error() string {
	return fmt.Sprintf(`geoip2: reader does not support the "%s" database type`,
		e.DatabaseType)
}

// Open takes a string path to a file and returns a DBReader struct or an error.
// The database file is opened using a memory map. Use the Close method on the
// DBReader object to return the resources to the system.
func Open(file string) (*DBReader, error) {
	reader, err := driver.Open(file)
	if err != nil {
		return nil, err
	}
	dbType, err := getDBType(reader)
	return &DBReader{reader, dbType}, err
}

func OpenByFile(f http.File) (*DBReader, error) {
	reader, err := driver.OpenByFile(f)
	if err != nil {
		return nil, err
	}
	dbType, err := getDBType(reader)
	return &DBReader{reader, dbType}, err
}

// FromBytes takes a byte slice corresponding to a GeoIP2/GeoLite2 database
// file and returns a DBReader struct or an error. Note that the byte slice is
// use directly; any modification of it after opening the database will result
// in errors while reading from the database.
func FromBytes(bytes []byte) (*DBReader, error) {
	reader, err := driver.FromBytes(bytes)
	if err != nil {
		return nil, err
	}
	dbType, err := getDBType(reader)
	return &DBReader{reader, dbType}, err
}

func getDBType(reader *driver.Reader) (databaseType, error) {
	switch reader.Metadata.DatabaseType {
	case "GeoIP2-Anonymous-IP":
		return isAnonymousIP, nil
	case "GeoLite2-ASN":
		return isASN, nil
	// We allow City lookups on Country for back compat
	case "GeoLite2-City",
		"GeoIP2-City",
		"GeoIP2-City-Africa",
		"GeoIP2-City-Asia-Pacific",
		"GeoIP2-City-Europe",
		"GeoIP2-City-North-America",
		"GeoIP2-City-South-America",
		"GeoIP2-Precision-City",
		"GeoLite2-Country",
		"GeoIP2-Country":
		return isCity | isCountry, nil
	case "GeoIP2-Connection-Type":
		return isConnectionType, nil
	case "GeoIP2-Domain":
		return isDomain, nil
	case "GeoIP2-Enterprise":
		return isEnterprise | isCity | isCountry, nil
	case "GeoIP2-ISP", "GeoIP2-Precision-ISP":
		return isISP, nil
	default:
		return 0, UnknownDatabaseTypeError{reader.Metadata.DatabaseType}
	}
}

// City takes an IP address as a net.IP struct and returns a City struct
// and/or an error. Although this can be used with other databases, this
// method generally should be used with the GeoIP2 or GeoLite2 City databases.
func (r *DBReader) City(ipAddress net.IP) (*City, error) {
	if isCity&r.databaseType == 0 {
		return nil, InvalidMethodError{"City", r.Metadata().DatabaseType}
	}
	var city City
	err := r.mmdbDBReader.Lookup(ipAddress, &city)
	return &city, err
}

// Country takes an IP address as a net.IP struct and returns a Country struct
// and/or an error. Although this can be used with other databases, this
// method generally should be used with the GeoIP2 or GeoLite2 Country
// databases.
func (r *DBReader) Country(ipAddress net.IP) (*Country, error) {
	if isCountry&r.databaseType == 0 {
		return nil, InvalidMethodError{"Country", r.Metadata().DatabaseType}
	}
	var country Country
	err := r.mmdbDBReader.Lookup(ipAddress, &country)
	return &country, err
}

// AnonymousIP takes an IP address as a net.IP struct and returns a
// AnonymousIP struct and/or an error.
func (r *DBReader) AnonymousIP(ipAddress net.IP) (*AnonymousIP, error) {
	if isAnonymousIP&r.databaseType == 0 {
		return nil, InvalidMethodError{"AnonymousIP", r.Metadata().DatabaseType}
	}
	var anonIP AnonymousIP
	err := r.mmdbDBReader.Lookup(ipAddress, &anonIP)
	return &anonIP, err
}

// ASN takes an IP address as a net.IP struct and returns a ASN struct and/or
// an error
func (r *DBReader) ASN(ipAddress net.IP) (*ASN, error) {
	if isASN&r.databaseType == 0 {
		return nil, InvalidMethodError{"ASN", r.Metadata().DatabaseType}
	}
	var val ASN
	err := r.mmdbDBReader.Lookup(ipAddress, &val)
	return &val, err
}

// ConnectionType takes an IP address as a net.IP struct and returns a
// ConnectionType struct and/or an error
func (r *DBReader) ConnectionType(ipAddress net.IP) (*ConnectionType, error) {
	if isConnectionType&r.databaseType == 0 {
		return nil, InvalidMethodError{"ConnectionType", r.Metadata().DatabaseType}
	}
	var val ConnectionType
	err := r.mmdbDBReader.Lookup(ipAddress, &val)
	return &val, err
}

// Domain takes an IP address as a net.IP struct and returns a
// Domain struct and/or an error
func (r *DBReader) Domain(ipAddress net.IP) (*Domain, error) {
	if isDomain&r.databaseType == 0 {
		return nil, InvalidMethodError{"Domain", r.Metadata().DatabaseType}
	}
	var val Domain
	err := r.mmdbDBReader.Lookup(ipAddress, &val)
	return &val, err
}

// ISP takes an IP address as a net.IP struct and returns a ISP struct and/or
// an error
func (r *DBReader) ISP(ipAddress net.IP) (*ISP, error) {
	if isISP&r.databaseType == 0 {
		return nil, InvalidMethodError{"ISP", r.Metadata().DatabaseType}
	}
	var val ISP
	err := r.mmdbDBReader.Lookup(ipAddress, &val)
	return &val, err
}

// Metadata takes no arguments and returns a struct containing metadata about
// the MaxMind database in use by the DBReader.
func (r *DBReader) Metadata() driver.Metadata {
	return r.mmdbDBReader.Metadata
}

// Close unmaps the database file from virtual memory and returns the
// resources to the system.
func (r *DBReader) Close() error {
	return r.mmdbDBReader.Close()
}

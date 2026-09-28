//! ngx_stream_geoip_module.c: variables with the country, organization and
//! city of the client address, looked up in the databases of the legacy
//! MaxMind GeoIP library (see ngx_core::geoip for the library binding).

use std::any::Any;
use std::ffi::c_ulong;
use std::mem::offset_of;
use std::net::Ipv6Addr;
use std::rc::Rc;

use ngx_core::cmd_fn;
use ngx_core::conf::*;
use ngx_core::geoip::*;
use ngx_core::inet::SockAddr;
use ngx_core::module::*;
use ngx_core::rc::*;
use ngx_core::string::B;

use crate::variables::*;
use crate::*;

stream_module_index!("ngx_stream_geoip_module");

const NGX_GEOIP_COUNTRY_CODE: usize = 0;
const NGX_GEOIP_COUNTRY_CODE3: usize = 1;
const NGX_GEOIP_COUNTRY_NAME: usize = 2;

const INADDR_NONE: c_ulong = 0xffffffff;

/// ngx_stream_geoip_conf_t
#[derive(Default)]
pub struct GeoipConf {
    pub country: Option<GeoIPDb>,
    pub org: Option<GeoIPDb>,
    pub city: Option<GeoIPDb>,
    pub country_v6: bool,
    pub org_v6: bool,
    pub city_v6: bool,
}

static GEOIP_VARS: &[VarDef] = &[
    VarDef { name: "geoip_country_code", set: None, get: Some(geoip_country_variable), data: NGX_GEOIP_COUNTRY_CODE, flags: 0 },
    VarDef { name: "geoip_country_code3", set: None, get: Some(geoip_country_variable), data: NGX_GEOIP_COUNTRY_CODE3, flags: 0 },
    VarDef { name: "geoip_country_name", set: None, get: Some(geoip_country_variable), data: NGX_GEOIP_COUNTRY_NAME, flags: 0 },
    VarDef { name: "geoip_org", set: None, get: Some(geoip_org_variable), data: 0, flags: 0 },
    VarDef { name: "geoip_city_continent_code", set: None, get: Some(geoip_city_variable), data: offset_of!(GeoIPRecord, continent_code), flags: 0 },
    VarDef { name: "geoip_city_country_code", set: None, get: Some(geoip_city_variable), data: offset_of!(GeoIPRecord, country_code), flags: 0 },
    VarDef { name: "geoip_city_country_code3", set: None, get: Some(geoip_city_variable), data: offset_of!(GeoIPRecord, country_code3), flags: 0 },
    VarDef { name: "geoip_city_country_name", set: None, get: Some(geoip_city_variable), data: offset_of!(GeoIPRecord, country_name), flags: 0 },
    VarDef { name: "geoip_region", set: None, get: Some(geoip_city_variable), data: offset_of!(GeoIPRecord, region), flags: 0 },
    VarDef { name: "geoip_region_name", set: None, get: Some(geoip_region_name_variable), data: 0, flags: 0 },
    VarDef { name: "geoip_city", set: None, get: Some(geoip_city_variable), data: offset_of!(GeoIPRecord, city), flags: 0 },
    VarDef { name: "geoip_postal_code", set: None, get: Some(geoip_city_variable), data: offset_of!(GeoIPRecord, postal_code), flags: 0 },
    VarDef { name: "geoip_latitude", set: None, get: Some(geoip_city_float_variable), data: offset_of!(GeoIPRecord, latitude), flags: 0 },
    VarDef { name: "geoip_longitude", set: None, get: Some(geoip_city_float_variable), data: offset_of!(GeoIPRecord, longitude), flags: 0 },
    VarDef { name: "geoip_dma_code", set: None, get: Some(geoip_city_int_variable), data: offset_of!(GeoIPRecord, dma_code), flags: 0 },
    VarDef { name: "geoip_area_code", set: None, get: Some(geoip_city_int_variable), data: offset_of!(GeoIPRecord, area_code), flags: 0 },
];

/// ngx_stream_geoip_addr
fn geoip_addr(s: &Session, _gcf: &GeoipConf) -> c_ulong {
    let addr = s.connection.sockaddr.borrow().clone();
    /* addr.name = s->connection->addr_text; */

    if let SockAddr::V6(sin6) = &addr {
        if let Some(inaddr) = sin6.ip().to_ipv4_mapped() {
            return u32::from(inaddr) as c_ulong;
        }
    }

    match &addr {
        SockAddr::V4(sin) => u32::from(*sin.ip()) as c_ulong,
        _ => INADDR_NONE,
    }
}

/// ngx_stream_geoip_addr_v6
fn geoip_addr_v6(s: &Session, _gcf: &GeoipConf) -> GeoIPv6 {
    let addr = s.connection.sockaddr.borrow().clone();
    /* addr.name = s->connection->addr_text; */

    let addr6 = match &addr {
        // Produce IPv4-mapped IPv6 address.
        SockAddr::V4(sin) => sin.ip().to_ipv6_mapped(),
        SockAddr::V6(sin6) => *sin6.ip(),
        _ => Ipv6Addr::UNSPECIFIED,
    };

    GeoIPv6 { s6_addr: addr6.octets() }
}

/// ngx_stream_geoip_country_variable
fn geoip_country_variable(s: &Session, v: &mut VariableValue, data: usize) -> i64 {
    let gcf = s.main_conf::<GeoipConf>(ctx_index());
    let gcf = gcf.borrow();

    let val = match &gcf.country {
        None => None,
        Some(country) => {
            if gcf.country_v6 {
                country.country_by_ipnum_v6(data, geoip_addr_v6(s, &gcf))
            } else {
                country.country_by_ipnum(data, geoip_addr(s, &gcf))
            }
        }
    };

    match val {
        None => {
            v.not_found = true;
        }

        Some(val) => {
            v.data = val;
            v.valid = true;
            v.no_cacheable = false;
            v.not_found = false;
        }
    }

    NGX_OK
}

/// ngx_stream_geoip_org_variable
fn geoip_org_variable(s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    let gcf = s.main_conf::<GeoipConf>(ctx_index());
    let gcf = gcf.borrow();

    let val = match &gcf.org {
        None => None,
        Some(org) => {
            if gcf.org_v6 {
                org.name_by_ipnum_v6(geoip_addr_v6(s, &gcf))
            } else {
                org.name_by_ipnum(geoip_addr(s, &gcf))
            }
        }
    };

    match val {
        None => {
            v.not_found = true;
        }

        Some(val) => {
            v.data = val;
            v.valid = true;
            v.no_cacheable = false;
            v.not_found = false;
        }
    }

    NGX_OK
}

/// ngx_stream_geoip_city_variable
fn geoip_city_variable(s: &Session, v: &mut VariableValue, data: usize) -> i64 {
    let gr = match geoip_get_city_record(s) {
        None => {
            v.not_found = true;
            return NGX_OK;
        }
        Some(gr) => gr,
    };

    match gr.str_member(data) {
        None => {
            // no_value: the record is deleted when gr is dropped
            v.not_found = true;
        }

        Some(val) => {
            v.data = val;
            v.valid = true;
            v.no_cacheable = false;
            v.not_found = false;
        }
    }

    NGX_OK
}

/// ngx_stream_geoip_region_name_variable
fn geoip_region_name_variable(s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    let gr = match geoip_get_city_record(s) {
        None => {
            v.not_found = true;
            return NGX_OK;
        }
        Some(gr) => gr,
    };

    let val = gr.region_name();

    drop(gr);

    match val {
        None => {
            v.not_found = true;
        }

        Some(val) => {
            v.data = val;
            v.valid = true;
            v.no_cacheable = false;
            v.not_found = false;
        }
    }

    NGX_OK
}

/// ngx_stream_geoip_city_float_variable
fn geoip_city_float_variable(s: &Session, v: &mut VariableValue, data: usize) -> i64 {
    let gr = match geoip_get_city_record(s) {
        None => {
            v.not_found = true;
            return NGX_OK;
        }
        Some(gr) => gr,
    };

    let val = gr.float_member(data);

    v.data.clear();
    sprintf_float(&mut v.data, val as f64, 4);
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;

    NGX_OK
}

/// ngx_stream_geoip_city_int_variable
fn geoip_city_int_variable(s: &Session, v: &mut VariableValue, data: usize) -> i64 {
    let gr = match geoip_get_city_record(s) {
        None => {
            v.not_found = true;
            return NGX_OK;
        }
        Some(gr) => gr,
    };

    let val = gr.int_member(data);

    v.data = val.to_string().into_bytes();
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;

    NGX_OK
}

/// ngx_stream_geoip_get_city_record
fn geoip_get_city_record(s: &Session) -> Option<GeoIPRecordPtr> {
    let gcf = s.main_conf::<GeoipConf>(ctx_index());
    let gcf = gcf.borrow();

    let city = gcf.city.as_ref()?;

    if gcf.city_v6 {
        city.record_by_ipnum_v6(geoip_addr_v6(s, &gcf))
    } else {
        city.record_by_ipnum(geoip_addr(s, &gcf))
    }
}

/// ngx_stream_geoip_add_variables
fn geoip_add_variables(cf: &mut Conf) -> ConfResult {
    add_variables(cf, GEOIP_VARS)
}

/// ngx_stream_geoip_create_conf: the databases are closed when the
/// configuration is freed (GeoIPDb::drop(), the ngx_stream_geoip_cleanup()
/// pool cleanup handler).
fn geoip_create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(GeoipConf::default())
}

/// ngx_stream_geoip_country
fn geoip_country(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let gcf = conf_rc::<GeoipConf>(conf.as_ref().expect("conf"));
    let mut gcf = gcf.borrow_mut();

    if gcf.country.is_some() {
        return Err(msg("is duplicate"));
    }

    conf_open(cf, &mut gcf.country)?;

    let ty = gcf.country.as_ref().expect("country").database_type();

    match ty {
        GEOIP_COUNTRY_EDITION => Ok(()),

        GEOIP_COUNTRY_EDITION_V6 => {
            gcf.country_v6 = true;
            Ok(())
        }

        _ => Err(cf.emerg(format_args!("invalid GeoIP database \"{}\" type:{}", B(&cf.args[1]), ty))),
    }
}

/// ngx_stream_geoip_org
fn geoip_org(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let gcf = conf_rc::<GeoipConf>(conf.as_ref().expect("conf"));
    let mut gcf = gcf.borrow_mut();

    if gcf.org.is_some() {
        return Err(msg("is duplicate"));
    }

    conf_open(cf, &mut gcf.org)?;

    let ty = gcf.org.as_ref().expect("org").database_type();

    match ty {
        GEOIP_ISP_EDITION | GEOIP_ORG_EDITION | GEOIP_DOMAIN_EDITION | GEOIP_ASNUM_EDITION => Ok(()),

        GEOIP_ISP_EDITION_V6 | GEOIP_ORG_EDITION_V6 | GEOIP_DOMAIN_EDITION_V6 | GEOIP_ASNUM_EDITION_V6 => {
            gcf.org_v6 = true;
            Ok(())
        }

        _ => Err(cf.emerg(format_args!("invalid GeoIP database \"{}\" type:{}", B(&cf.args[1]), ty))),
    }
}

/// ngx_stream_geoip_city
fn geoip_city(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let gcf = conf_rc::<GeoipConf>(conf.as_ref().expect("conf"));
    let mut gcf = gcf.borrow_mut();

    if gcf.city.is_some() {
        return Err(msg("is duplicate"));
    }

    conf_open(cf, &mut gcf.city)?;

    let ty = gcf.city.as_ref().expect("city").database_type();

    match ty {
        GEOIP_CITY_EDITION_REV0 | GEOIP_CITY_EDITION_REV1 => Ok(()),

        GEOIP_CITY_EDITION_REV0_V6 | GEOIP_CITY_EDITION_REV1_V6 => {
            gcf.city_v6 = true;
            Ok(())
        }

        _ => Err(cf.emerg(format_args!("invalid GeoIP City database \"{}\" type:{}", B(&cf.args[1]), ty))),
    }
}

pub fn geoip_module() -> ModuleDef {
    stream_module_def(
        "ngx_stream_geoip_module",
        StreamModuleDef {
            preconfiguration: Some(geoip_add_variables),
            create_main_conf: Some(geoip_create_conf),
            ..Default::default()
        },
        vec![
            cmd_fn!("geoip_country", NGX_STREAM_MAIN_CONF | NGX_CONF_TAKE12, ConfLevel::Main, geoip_country),
            cmd_fn!("geoip_org", NGX_STREAM_MAIN_CONF | NGX_CONF_TAKE12, ConfLevel::Main, geoip_org),
            cmd_fn!("geoip_city", NGX_STREAM_MAIN_CONF | NGX_CONF_TAKE12, ConfLevel::Main, geoip_city),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variables_table_as_in_c() {
        let names: Vec<&str> = GEOIP_VARS.iter().map(|v| v.name).collect();
        assert_eq!(
            names,
            [
                "geoip_country_code",
                "geoip_country_code3",
                "geoip_country_name",
                "geoip_org",
                "geoip_city_continent_code",
                "geoip_city_country_code",
                "geoip_city_country_code3",
                "geoip_city_country_name",
                "geoip_region",
                "geoip_region_name",
                "geoip_city",
                "geoip_postal_code",
                "geoip_latitude",
                "geoip_longitude",
                "geoip_dma_code",
                "geoip_area_code",
            ]
        );
        assert_eq!(GEOIP_VARS[4].data, 72);
        assert_eq!(GEOIP_VARS[13].data, 52);
        assert_eq!(GEOIP_VARS[14].data, 56);
    }
}

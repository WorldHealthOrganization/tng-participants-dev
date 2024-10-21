import pycountry
import pytest
from common import requires_readable_cert
from cryptography import x509


def add_country(db, **params):
    '''Add a country to a pycountry database for the duration of this session.
       This is useful to patch testing countries into a list of countries.'''
    if not db._is_loaded:
        db._load()
    # Create an instance of the virtual country
    obj = db.data_class(**params)
    # Add it to the database
    db.objects.append(obj)
    # Update the indices
    for key, value in params.items():
        value = value.lower()
        if key in db.no_index:
            continue
        index = db.indices.setdefault(key, {})
        index[value] = obj


@requires_readable_cert
def test_country_flag(cert, pytestconfig):
    'The country flag (C value) must be set to the correct country code'

    add_country(pycountry.countries, alpha_2='XA', alpha_3='XXA', common_name='Test XA',
                                         flag='😄', name='Test XA', numeric='23233', official_name='Test Country XA' )
    add_country(pycountry.countries, alpha_2='XB', alpha_3='XXB', common_name='Test XA',
                                     flag='😄', name='Test XXB', numeric='2929', official_name='Test Country XB' )
    add_country(pycountry.countries, alpha_2='XY', alpha_3='XXY', common_name='Test XY',
                                     flag='😄', name='Test XY', numeric='9989', official_name='Test Country XY' )
    add_country(pycountry.countries, alpha_2='XX', alpha_3='XXX', common_name='Test XA',
                                     flag='😄', name='Test XX', numeric='9990', official_name='Test Country XX' )
    add_country(pycountry.countries, alpha_2='XL', alpha_3='XCL', common_name='Test LAC (XL, XCL)',
                                     flag='😄', name='Test XL', numeric='9991', official_name='Test Country XL' )
    add_country(pycountry.countries, alpha_2='XO', alpha_3='XXO', common_name='Test XO',
                                     flag='😄', name='Test XO', numeric='9992', official_name='Test Country XO' )
    add_country(pycountry.countries, alpha_2='XM', alpha_3='XML', common_name='Test XM',
                                     flag='😄', name='Test XM', numeric='9993', official_name='Test Country XM' )
    add_country(pycountry.countries, alpha_2='XC', alpha_3='XXC', common_name='Test XC',
                                     flag='😄', name='Test XC', numeric='9994', official_name='Test Country XC' )
    add_country(pycountry.countries, alpha_2='JA', alpha_3='XJA', common_name='Test JA',
                                     flag='😄', name='Test JA', numeric='9995', official_name='Test Country XJA' )
    add_country(pycountry.countries, alpha_2='XD', alpha_3='XXD', common_name='Test XD',
                                     flag='😄', name='Test XD', numeric='9997', official_name='Test Country XXD' )
    add_country(pycountry.countries, alpha_2='XE', alpha_3='XXE', common_name='Test XE',
                                     flag='😄', name='Test XE', numeric='9998', official_name='Test Country XXE' )
    add_country(pycountry.countries, alpha_2='XG', alpha_3='XXG', common_name='Test XG',
                                     flag='😄', name='Test XG', numeric='9999', official_name='Test Country XXG' )
    add_country(pycountry.countries, alpha_2='XH', alpha_3='XXH', common_name='Test XH',
                                     flag='😄', name='Test XH', numeric='8880', official_name='Test Country XXH' )
    add_country(pycountry.countries, alpha_2='XF', alpha_3='XXF', common_name='Test XF',
                                     flag='😄', name='Test XF', numeric='8881', official_name='Test Country XXF' )
    add_country(pycountry.countries, alpha_2='XJ', alpha_3='XXJ', common_name='Test XJ',
                                     flag='😄', name='Test XJ', numeric='8882', official_name='Test Country XXJ' )
    add_country(pycountry.countries, alpha_2='XK', alpha_3='XXK', common_name='Test XK',
                                     flag='😄', name='Test XK', numeric='8883', official_name='Test Country XXK' )
    add_country(pycountry.countries, alpha_2='XI', alpha_3='XXI', common_name='Test XI',
                                     flag='😄', name='Test XI', numeric='8884', official_name='Test Country XXI' )
    add_country(pycountry.countries, alpha_2='XQ', alpha_3='XXQ', common_name='Test XQ',
                                     flag='😄', name='Test XQ', numeric='8885', official_name='Test Country XXQ' )
    countries = list(pycountry.countries)

    if not pytestconfig.getoption('country_mode'): 
        pytest.skip(reason='This test only runs in country mode')

    country_attributes = cert.x509.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)
    
    if not country_attributes:
        # Check 1: Country attribute must be present
        assert False, 'No country attribute found'
    else:
        # Check 2: Country must be in the list of existing countries
        country = pycountry.countries.lookup(country_attributes[0].value)

    # Check 3: Country in path must match country of C attribute
    assert cert.pathinfo.get('country') == country.alpha_3, f"{cert.pathinfo.get('country')} != {country.alpha_3}"

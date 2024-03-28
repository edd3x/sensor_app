import os
import io
import sys
import json
import glob
import solara
import leafmap
import requests
import pandas as pd
import geopandas as gp
from datetime import datetime
from shutil import rmtree
from shapely import Point, box, to_geojson, to_wkt

import reacton.ipywidgets as widgets
import reacton.ipyvuetify as v
from solara.components.file_drop import FileInfo
from solara.lab.components.confirmation_dialog import ConfirmationDialog

#########################################################################
########################## REQUIRED META DATA ###########################
#########################################################################
backend_url = os.environ.get('SENSOR_API')
schemas = json.load(open('./schema_meta.json'))
date_time_stamp = datetime.now()

#########################################################################
####################### SOLARA REACTIVE VARIABLES #######################
#########################################################################
zoom = solara.reactive(10.5)
center = solara.reactive((56.11, -3.93))

login_msg = solara.reactive("Log in to the Forth-ERA Sensor API")
username = solara.reactive("")
password = solara.reactive("")
sensorUID = solara.reactive("")
latitude = solara.reactive(None)
longitude = solara.reactive(None)
taskOps = solara.reactive("")
task = solara.reactive("")
task_types = ["","Single Update", "Bulk Update"]

multi_sensors = solara.reactive(False)
multi_params = solara.reactive(False)
show_schema = solara.reactive(False)
meta_string = solara.reactive(None)


platform_meta_string = solara.reactive(None)
platform_location_meta_string = solara.reactive(None)
sensor_location_meta_string = solara.reactive(None)
sensor_meta_string = solara.reactive(None)
param_meta_string = solara.reactive(None)
platform_calibration_meta_string = solara.reactive(None)
platform_maintenance_meta_string = solara.reactive(None)

string_check_info = solara.reactive(None)
csv_check_info = solara.reactive(None)
error_ = solara.reactive(None)
show_dialog = solara.reactive(False)
continuous_update = solara.reactive(True)
sensor_map = solara.reactive(None)

api_response_records = []

#########################################################################
################# GEOMETRY FOR LOCATION INSTALLED SENSORS################
#########################################################################
stations_packet = {
        "sensor_uids":None,
        "measurands": None,
        "dissolve_on_location": False, # Dissolution on location (if True devices come as nested array, False comes flat)
        "geom": { # geojson string needs to be a standard feature collection
                    "type": "FeatureCollection",
                    "name": "test",
                    "crs": {
                    "type": "name",
                    "properties": {
                        "name": "urn:ogc:def:crs:OGC:1.3:CRS84"
                        }
                        },
                        "features": [
                        {
                            "type": "Feature",
                            "properties": {},
                            "geometry": {
                            "type": "Polygon",
                            "coordinates": [
                                [
                                [-4.645574908527635,56.589629977460106],
                                [-4.645574908527635,55.40055948153838],
                                [-2.459260350828032,55.40055948153838],
                                [-2.459260350828032,56.589629977460106],
                                [-4.645574908527635,56.589629977460106]
                                ]
                            ]
                            }
                        }
                        ]
                    }
                    }

sensor_attrib = [
    'platform_uid',
    'location_name',
    'last_recorded_timestamp',
    'geometry']

useCaseDashboard = [
    "air quality",
    "biodiversity",
    "floods",
    "peatlands",
    "water quality",
    "demo"]

sensorCategory =[
    "Air",
    "Land",
    "Water"]

sensorSubCategory = [
    "Urban Area",
    "Industrial Area",
    "Peatland",
    "Nature Reserve",
    "Loch",
    "Reservoir",
    "River",
    "Estuary"]



#########################################################################
################# LEAFMAP CLASS TO SHOW SENSOR LOCATIONS ###############
#########################################################################
class Map(leafmap.Map):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if sensor_map.value is not None:
            self.add_gdf(gdf=sensor_map.value, layer_name='Sensor Locations', zoom_to_layer=True, info_mode='on_click')

#########################################################################
################# CLASS TO GENERATE DOUBLE QUOTES FOR METADATA############
#########################################################################      
class doubleQuoteDict(dict):
        def __str__(self):
            return json.dumps(self)

        def __repr__(self):
            return json.dumps(self)


#########################################################################
################# GEOMETRY FOR LOCATION INSTALLED SENSORS ###############
#########################################################################     
@solara.component
def meta_input(value_src):
    solara.InputText(label='Enter the json string', value=value_src, continuous_update=continuous_update.value)
    if value_src.value is not None:
        solara.Info(label='All keys and values in the json string must have double quotes', icon=True)

@solara.component
def show_eg_schema(eg_schema):
    if show_schema.value:
        example = f'Example string: {eg_schema}'
        solara.HTML(tag='code', unsafe_innerHTML=example)

@solara.component
def file_input_details(schema, name, file_handler):
    name = name.replace(' ', '_')
    print(name)
    temp_df = pd.DataFrame(schema, index=[0])
    if 'static_attributes' in temp_df.columns:
        temp_df['static_attributes'] = str(doubleQuoteDict(schema['static_attributes']))

    solara.FileDownload(data=temp_df.to_csv(index=False), filename=f'template_for_{name}.csv', label=f'Get Template')
    solara.Markdown(md_text='Upload CSV file')
    solara.FileDrop(label='Drop CSV file here...',on_file=file_handler ,lazy=True)
                

#########################################################################
############################ MAIN APP PAGE ##############################
#########################################################################  
@solara.component
def Page():
    ############################ VARIABLE STATES ##############################
    task_type, set_task_type = solara.use_state(None)
    api_task, set_api_task = solara.use_state(None)
    content, set_content = solara.use_state(b"")
    platform_content, set_platform_content = solara.use_state(b"")
    sensor_content, set_sensor_content = solara.use_state(b"")
    platform_location_content, set_platform_location_content = solara.use_state(b"")
    sensor_location_content, set_sensor_location_content = solara.use_state(b"")
    param_content, set_param_content = solara.use_state(b"")
    calibration_content, set_calibration_content = solara.use_state(b"")
    maintenance_content, set_maintenance_content = solara.use_state(b"")

    auth, set_auth = solara.use_state(None)
    session, set_session = solara.use_state(None)
    api_response, set_response = solara.use_state(None)
    sensor, set_sensor = solara.use_state(None)
    tag_verified, set_tag_verified = solara.use_state('All Good')

    latitude_, set_latitude = solara.use_state(None)
    longitude_, set_longitude= solara.use_state(None)
    open_login, set_open_login = solara.use_state(False)
    logged_in, set_logged_in = solara.use_state(False)
    
    error_.set(None)
    
    response_records, set_response_records = solara.use_state(None)
    
    ############################ CLEAN LOGS ##############################
    # logs = glob.glob('./logs/*txt')
    # if 
    # for file in glob.glob('./logs/*txt'):
    #     if os.path.exists(file):
    #         rmtree(file)
    
    ############################ FUNCTIONS ##############################
    def tag_verification(tag_list:list, accepted_tags:list):
        for t in tag_list:
            print(t)
            if t not in accepted_tags:
                set_tag_verified(f'The "{t}" tag is not in accepted tags {accepted_tags}')
                sys.exit(1)
                
    def taskType(type: str):
        set_task_type(type)

    def apiTask(type: str):
        set_api_task(type)

    def setSensorID(type: str):
        set_sensor(type)

    def setCoords(lat: float, lon: float):
        set_latitude(lat)
        set_longitude(lon)
        
    def toggle_login():
        if open_login:
            set_open_login(False)
        set_logged_in(not logged_in)
        set_open_login(True)

    def close_login():
        set_open_login(False)

    ############################ AUTH FUNCTIONS ##############################
    def authenticate(_username, _password):
        try:
            # Read write access
            login_data = {
            "username": _username,
            "password": _password,
            }
            session = requests.Session()
            response = requests.post(backend_url + 'token', login_data,timeout=3)
            response = json.loads(response.content.decode('utf-8'))
            session.headers.update({"Authorization": 'Bearer ' + response['access_token']})
            # print(session, type(session))

            set_session(session)
            if len(response['access_token']) == 0:
                set_auth('Fail')
            if len(response['access_token']) > 0:
                set_auth('Success')
        except:
            if _username == "":
                set_auth('Check username and password')

    
    
    ############################ API POST QUERY FUNCTION ##############################
    def post_query_endpoint(packet,endpoint):
        print('making a call to endpoint -',endpoint) 
        response  = session.post(backend_url + endpoint, json=packet,timeout=20)
        code = response.status_code
        if code == 200:
            print('Successful response')
            return response.text
        else:
            if code > 200 and code < 500:
                # Typically these errors are thrown for duplicate records 
                print('Bad response')
                print(response.text)
            
            else:
                print('Server error')
                # print(response.text)
    
    ############################ API POST QUERY SINGLE UPDATE ##############################
    def query_endpoint_single(packet,endpoint):
        error_.set(None)
        set_tag_verified('All Good')
        try:
            packet_ = doubleQuoteDict(json.loads(packet))
            print(packet_)
            if 'platform_env_category' in packet_.keys():
                print('Checking platform_env_category tags')
                tag_verification([packet_['platform_env_category']], sensorCategory)

            if 'platform_env_sub_category' in packet_.keys():
                print('Checking platform_env_sub_category tags')
                tag_verification(packet_['platform_env_sub_category'], sensorSubCategory)
            
            if 'sensor_env_category' in packet_.keys():
                print('Checking sensor_env_category')
                tag_verification([packet_['sensor_env_category']], sensorCategory)

            if 'sensor_env_sub_category' in packet_.keys():
                print('Checking sensor_env_sub_category tags')
                tag_verification(packet_['sensor_env_sub_category'], sensorSubCategory)
                
            if 'use_case_dashboard' in packet_.keys():
                print('Checking use_case_dashboard tags')
                tag_verification(packet_['use_case_dashboard'], useCaseDashboard)
            
            if 'dataset_envelope' in packet_.keys():
                print(packet_['dataset_envelope'])
                lon = packet_['dataset_envelope'][0]
                lat = packet_['dataset_envelope'][1]
                packet_['dataset_envelope'] = to_wkt(box(*Point(lon, lat).buffer(0.00005).envelope.bounds))
            
            print('making a call to endpoint -',endpoint) 
            response  = session.put(backend_url + endpoint, json=packet_,timeout=20)
            code = response.status_code
            if code == 200:
                print('Successful response')
                print('API Says:', response.text)
                set_response(f'Successful response: {response.text}')
                api_response_records.append(f'{date_time_stamp} - Successful response: {response.text}')
            else:
                if code > 200 and code < 500:
                    # Typically these errors are thrown for duplicate records 
                    print('Bad response')
                    print('API Says:', response.text)
                    set_response(f'Bad response: {response.text}')
                    api_response_records.append(f'{date_time_stamp} - Bad response: {response.text}')
                    
                else:
                    print('Server error')
                    set_response('Server error')
            set_response_records(api_response_records)
        except:
            error_.set(f'Check Tags')

    ############################ API POST QUERY BULK UPDATE ##############################
    def query_endpoint_bulk(data, endpoint):
        set_tag_verified('All Good')
        try:
            print('loading...')
            for mdata in data.iterrows():
                packet = doubleQuoteDict(mdata[1].to_dict())
                packet = mdata[1].to_dict()

                if 'limits' in mdata[1].to_dict().keys():
                    packet['limits'] = [int(l) for l in mdata[1]['limits'].strip('][').split(',')]

                if 'platform_env_category' in mdata[1].to_dict().keys():
                    tag_verification([packet['platform_env_category']], sensorCategory)
                
                if 'sensor_env_category' in mdata[1].to_dict().keys():
                    print('Checking sensor_env_category tags')
                    tag_verification([packet['sensor_env_category']], sensorCategory)

                if 'platform_env_sub_category' in mdata[1].to_dict().keys():
                    packet['platform_env_sub_category'] = [l for l in mdata[1]['platform_env_sub_category'].strip('][').split(',')]
                    tag_verification(packet['platform_env_sub_category'], sensorSubCategory)
                
                if 'sensor_env_sub_category' in mdata[1].to_dict().keys():
                    print('Checking sensor_env_sub_category tags')
                    print([l for l in mdata[1]['sensor_env_sub_category'].strip('][').split(',')])
                    packet['sensor_env_sub_category'] = [l for l in mdata[1]['sensor_env_sub_category'].strip('][').split(',')]
                    tag_verification(packet['sensor_env_sub_category'], sensorSubCategory)
                
                if 'use_case_dashboard' in mdata[1].to_dict().keys():
                    print('Checking use_case_dashboard tags')
                    packet['use_case_dashboard'] = [l for l in mdata[1]['use_case_dashboard'].strip('][').split(',')]
                    tag_verification(packet['use_case_dashboard'], useCaseDashboard)
                
                if 'static_attributes' in mdata[1].to_dict().keys():
                    packet['static_attributes'] = json.loads(mdata[1]['static_attributes'])
                
                if 'notes' in mdata[1].to_dict().keys():
                    packet['notes'] = json.loads(mdata[1]['notes'])
                
                if 'platform_communication_details' in mdata[1].to_dict().keys():
                    packet['platform_communication_details'] = json.loads(mdata[1]['platform_communication_details'])
                
                if 'sensor_calibration_parameters' in mdata[1].to_dict().keys():
                    packet['sensor_calibration_parameters'] = json.loads(mdata[1]['sensor_calibration_parameters'])
                    
                if 'dataset_envelope' in mdata[1].to_dict().keys():
                    print(mdata[1]['dataset_envelope'])
                    lon = mdata[1]['dataset_envelope'].strip('][').split(',')[0]
                    lat = mdata[1]['dataset_envelope'].strip('][').split(',')[1]
                    # geom_wkt = to_wkt(box(*Point(lon, lat).buffer(0.00005).envelope.bounds))
                    packet['dataset_envelope'] = to_wkt(box(*Point(lon, lat).buffer(0.00005).envelope.bounds))
                
                print(packet)

                print('making a call to endpoint -',endpoint) 
                response  = session.put(backend_url + endpoint, json=packet,timeout=20)
                code = response.status_code
                print(code)
                if code == 200:
                    print('Successful response')
                    print('API Says:', response.text)
                    # records.append(json.loads(response.text)["messages"][1])
                    set_response(f'Successful response: {response.text}')
                    api_response_records.append(f'{date_time_stamp} - Successful response: {response.text}')
                else:
                    if code > 200 and code < 500:
                        # Typically these errors are thrown for duplicate records 
                        print('Bad response')
                        print('API Says:', response.text)
                        set_response(f'Bad response: {response.text}')
                        api_response_records.append(f'{date_time_stamp} - Bad response: {response.text}')
                        
                    else:
                        print('Server error')
                        set_response('Server error')
                        # print(response.text)
            set_response_records(api_response_records)
        except:
            error_.set(f'Check CSV files:{tag_verified.value}')

    # Function for a single platform registration
    def upload_single_platform(string_values, endpoints_keys):
        set_tag_verified('All Good')
        if not bulk_upload:
            checks = {endpoint_:string.value for endpoint_, string in zip(endpoints_keys, string_values)}
            none_names = []
            for name in checks.keys():
                print(type(checks[name]))
                if checks[name] == None:
                    none_names.append(name)
            if len(none_names) != 0:
                string_check_info.set(none_names)
            else:
                for endpoint_key, packet in zip(endpoints_keys, string_values):
                    endpoint = schemas["put_endPoints"][endpoint_key]
                    print(endpoint,packet.value, type(packet.value))
                    query_endpoint_single(endpoint=endpoint, packet=packet.value)

    # Function for a single sensor registration
    def upload_single_sensor(string_values, csv_data, endpoints_keys, bulk_upload):
        set_tag_verified('All Good')
        if not bulk_upload:
            checks = {endpoint_:string.value for endpoint_, string in zip(endpoints_keys, string_values)}
            none_names = []
            for name in checks.keys():
                print(type(checks[name]))
                if checks[name] == None:
                    none_names.append(name)
            if len(none_names) != 0:
                string_check_info.set(none_names)
            else:
                for endpoint_key, packet in zip(endpoints_keys, string_values):
                    endpoint = schemas["put_endPoints"][endpoint_key]
                    query_endpoint_single(endpoint=endpoint, packet=packet.value)
                
        if bulk_upload:
            try:
                param_df = pd.read_csv(io.BytesIO(csv_data[0]))

                if len(param_df) == 0:
                    csv_check_info.set('No data in CSV file')
                    print('No data in CSV file')

                else:
                    for endpoint_key in endpoints_keys:
                        endpoint = schemas["put_endPoints"][endpoint_key]
                        query_endpoint_single(endpoint=endpoint, packet=packet)

                        if endpoint_key == "Register a sensor parameter ":
                            query_endpoint_bulk(param_df, schemas["put_endPoints"]["Register a sensor parameter "])

            except:
                csv_check_info.set('No CSV Uploaded')
                print('No CSV Uploaded')


    # Function for a registering platform and sensors in bulk or batches 
    def bulk_upload(csv_data, endpoints_keys):
        set_tag_verified('All Good')
        try:
            for data, endpoint_key in zip(csv_data, endpoints_keys):
                packet_df = pd.read_csv(io.BytesIO(data))
                print(packet_df)

                if len(packet_df) == 0:
                    csv_check_info.set('No data in CSV file')
                    print('No data in CSV file')
                
                print(schemas["put_endPoints"][endpoint_key])
                query_endpoint_bulk(packet_df, schemas["put_endPoints"][endpoint_key])
        except:
            csv_check_info.set('No CSV Uploaded')
            print('No CSV Uploaded')


    def on_file(file: FileInfo):
        f = file["file_obj"]
        set_content(f.read())

    def on_file_platforms(file: FileInfo):
        print(file["name"])
        f = file["file_obj"]
        set_platform_content(f.read())

    def on_file_platform_location(file: FileInfo):
        print(file["name"])
        f = file["file_obj"]
        set_platform_location_content(f.read())

    def on_file_sensor_location(file: FileInfo):
        print(file["name"])
        f = file["file_obj"]
        set_sensor_location_content(f.read())

    def on_file_sensors(file: FileInfo):
        print(file["name"])
        f = file["file_obj"]
        set_sensor_content(f.read())

    def on_file_params(file: FileInfo):
        print(file["name"])
        f = file["file_obj"]
        set_param_content(f.read())
        
    def on_file_calibration_location(file: FileInfo):
        print(file["name"])
        f = file["file_obj"]
        set_calibration_content(f.read())
    
    def on_file_maintenance_history(file: FileInfo):
        print(file["name"])
        f = file["file_obj"]
        set_maintenance_content(f.read())
        

    home_text = """
        <p style="text-align:center;font-size: 20px; line-height: 35px">Welcome to the ForthERA sensors API web interface. </br>
        This web interface will enable you to interact with the sensor API, </br> 
        create new meta data for newly installed field sensors and update meta data for existing sensors</p>
    """
    css =""".head{
                background-color:cornflowerblue !important; 
                
                }
            .h-task div{
                text-align:center !important;
            }
            .solara-markdown p{font-size: 20px;
                                font-weight: 300;
                                }
            .v-card {width: 100%;
                                font-weight: 300;
                                }
            .v-sheet {row-gap:0px !important;}
            .tsk-btn span {color:#fff;}

            
                        }
                """ 
    with solara.Head():
        solara.Title('Sensor API Interface')
        solara.Style(css)

    with ConfirmationDialog(title='Log in to the Forth-ERA Sensor API', 
                            open=open_login, 
                            cancel='Close', 
                            ok='Okay!!',
                            on_ok= lambda: close_login):
        with solara.Column(gap='15px'):
            solara.InputText(label='Enter your username', value=username, continuous_update=continuous_update.value)
            solara.InputText(label="Enter your password", value=password, continuous_update=continuous_update.value, password=True)
            solara.Button("Authenticate", on_click=lambda: authenticate(username.value, password.value))

            print('auth is', auth)
            if auth =='Fail':
                solara.Error(label='Authentication Failed', icon=True)
            if auth =='Success':
                solara.Success(label='Login successful', icon=True)
                set_open_login(False)
    
    
    with solara.AppBarTitle():
        solara.Text("Sensor Web Interface")
        
    with solara.AppBar():
        icon_name = "mdi-logout" if logged_in else "mdi-login"
        label_name = "Logout" if auth =='Success' else "Login"
        solara.Button(label=label_name,icon_name=icon_name , on_click=toggle_login, icon=False)
    

    with solara.Card():
        # solara.HTML(tag='div', unsafe_innerHTML=home_head)
        solara.HTML(tag='div', unsafe_innerHTML=home_text,classes=['home'])


    if auth =='Success':
        with solara.Card():
            with solara.Row(gap="10px", justify='center'):
                solara.Button(label="Upload Metadata", on_click=lambda: apiTask("upload"), color='#1976d2', classes=['tsk-btn'])
                solara.Button(label="View Metadata", on_click=lambda: apiTask("view"), color='#056a18', classes=['tsk-btn'])
                solara.Button(label="View Sensor Map", on_click=lambda: apiTask("map"), color='#887002', classes=['tsk-btn'])
    
    if api_task == 'map':
        listings = post_query_endpoint(stations_packet , endpoint='sensors/listAllStationDevices')
        
        sensor_map.set(gp.read_file(json.dumps(json.loads((listings))['data']),driver='GeoJSON').drop(columns=['id']).loc[:,sensor_attrib])
        with solara.Column(style={"min-width": "500px", "height": "100vh"," width": "100vw"},classes=['main']):
            Map.element(  # type: ignore
            zoom=zoom.value,
            center=center.value,
            scroll_wheel_zoom=True,
            toolbar_control = False,
            draw_control = False,
            height = "70%"
            )            
    
    if api_task =='view':
        with solara.Card(title='Select Item to View'):
            solara.Markdown(md_text='I want to:')
            solara.Select(label='Select a view task', value=taskOps, values=list(schemas['get_endPoints'].keys()))
            print('selected', schemas['get_endPoints'][taskOps.value])
            if taskOps.value == "": 
                solara.Markdown(md_text='No view endpoint selected')
            elif (taskOps.value == "Get calibration history of device") or (taskOps.value == "Get maintenance history of device"):
                solara.InputText(label='Enter sensor_uid', value=sensorUID, continuous_update=continuous_update.value)
                solara.Button(label="Submit", on_click=lambda: setSensorID(sensorUID.value), color='#1976d2', classes=['tsk-btn'])
                
                if (sensor != None) & (taskOps.value != ""):
                    endpoint = schemas['get_endPoints'][taskOps.value].replace('{sensor_uid}', sensor)
                    print(endpoint)
                    item_json = session.get(backend_url + endpoint)
                    solara.DataFrame(pd.DataFrame(json.loads(item_json.text)['data']))
            else:
                item_json = session.get(backend_url + schemas['get_endPoints'][taskOps.value])
                print(item_json)
                # solara.DataFrame(pd.DataFrame(json.loads(item_json.text)['data']))
                dataframe = pd.DataFrame(json.loads(item_json.text)['data'])

                solara.CrossFilterSelect(dataframe, dataframe.columns[0])
                solara.CrossFilterDataFrame(dataframe)
            

    if api_task =='upload':
        with solara.Card(title='Select an API tasks'):
            solara.Markdown(md_text='I want to:')
            task_list = list(schemas['put_endPoints'].keys())
            solara.Select(label='Select an API task', value=task, values=[t for t in task_list if not t.startswith('Attach') ])
            with solara.Row(gap="10px"):
                solara.Button(label="Single Upload", on_click=lambda: taskType("single"), color='#1976d2', classes=['tsk-btn'])
                solara.Button(label="Bulk Upload", on_click=lambda: taskType("bulk"), color='#1976d2', classes=['tsk-btn'])
                

            task_schema = schemas["endpoint_schemas"][schemas["put_endPoints"][task.value]]

        # Register a single platform, a platform location, with one or many sensors and parameters
        if (task_type == "single") & (task.value=="Register a new platform "):
            solara.Switch(label="Show example schemas", value=show_schema)
            with solara.Row():
                with solara.GridFixed(columns=3):
                    with solara.Card(title='Step 1: Register Platform'):
                        solara.Markdown(md_text='Enter a platform metadata, see schema below')
                        show_eg_schema(doubleQuoteDict(task_schema))
                        meta_input(platform_meta_string)
                        
                    with solara.Card(title='Step 2: Register Platform Location'):
                        solara.Markdown(md_text='Enter a platform location metadata, see format below')
                        show_eg_schema(doubleQuoteDict(schemas["endpoint_schemas"][schemas["put_endPoints"]["Install a device at a location "]]))
                        meta_input(platform_location_meta_string)
                        
                    with solara.Card(title='Step 3: Add Device to Platform'):
                        solara.Markdown(md_text='Enter Device metadata, see format below')
                        show_eg_schema(doubleQuoteDict(schemas["endpoint_schemas"][schemas["put_endPoints"]["Attach a new sensor to a platform "]]))
                        meta_input(sensor_meta_string)
                            
                    with solara.Card(title='Step 4: Register Device Location'):
                        solara.Markdown(md_text='Enter metadata for device location, see format below')
                        show_eg_schema(doubleQuoteDict(schemas["endpoint_schemas"][schemas["put_endPoints"]["Install a device at a location "]]))
                        meta_input(sensor_location_meta_string)
                    
                    with solara.Card(title='Step 5: Add device calibration and maintenance history'):
                        solara.Markdown(md_text='Enter the information on device calibration, see format')
                        show_eg_schema(doubleQuoteDict(schemas["endpoint_schemas"][schemas["put_endPoints"]["Update platform calibration "]]))
                        meta_input(platform_calibration_meta_string)
                        
                        solara.Markdown(md_text='Enter the information on maintenance history, see format')
                        show_eg_schema(doubleQuoteDict(schemas["endpoint_schemas"][schemas["put_endPoints"]["Update platform maintenance "]]))
                        meta_input(platform_maintenance_meta_string)
                    
                    with solara.Card(title='Step 6: Register Device Parameters'):
                        solara.Markdown(md_text='Enter metadata for device parameters, see format below')
                        show_eg_schema(doubleQuoteDict(schemas["endpoint_schemas"][schemas["put_endPoints"]["Register a sensor parameter "]]))
                        meta_input(platform_location_meta_string)

            if api_response is not None:
                    solara.Info(api_response, icon=True)
            
            use_endpoint_keys = ["Register a new platform ", "Install a device at a location ", "Attach a new sensor to a platform ","Install a device at a location ","Update platform calibration ", "Update platform maintenance ", "Register a sensor parameter "]
            meta_string_values = [platform_meta_string, platform_location_meta_string, sensor_meta_string, sensor_location_meta_string, platform_calibration_meta_string, platform_maintenance_meta_string, param_meta_string]
            
            with solara.Row(style={'padding-bottom':'30px'}):
                with solara.HBox():
                    solara.Button("Upload Metadata", color='#1976d2', classes=['tsk-btn'], on_click=lambda: upload_single_platform(string_values = meta_string_values, endpoints_keys = use_endpoint_keys))
                    
                    if error_.value is not None:
                        solara.Warning(error_.value, icon=True)

                    if csv_check_info.value  is not None:
                        solara.Warning(csv_check_info.value, icon=True)

                    if string_check_info.value is not None:
                        for msg in string_check_info.value:
                            print(msg)
                            solara.Warning(f'No metadata entered for "{msg}"', icon=True)

                    if response_records is not None:
                        print(response_records)
                        logfile = open('logs/upload_log.txt','w')
                        for record in response_records:
                            logfile.write(record+"\n")
                        logfile.close()
                            
                        solara.FileDownload(data=open(f'./logs/upload_log.txt', "rb"), filename=f'upload_log_at_{date_time_stamp}.txt', label=f'Get Logs')
                        

        # Register a or update other metadata (single)
        if (task_type == "single") & (task.value != "Attach a new sensor to a platform ") & (task.value!="Register a new platform "):
            with solara.Card():
                solara.Markdown(md_text='Enter a metadata in the format shown below')
                example = f'Example string: {doubleQuoteDict(task_schema)}'
                solara.HTML(tag='code', unsafe_innerHTML=example)
                
                solara.InputText(label='Enter the json string', value=meta_string, continuous_update=continuous_update.value)
                if meta_string.value is not None:
                    solara.Info(label='All keys and values in the json string must have double quotes', icon=True)

                if api_response is not None:
                    solara.Info(api_response, icon=True)

                with solara.Row(style={'padding-bottom':'30px'}):
                    with solara.HBox():
                        solara.Button("Upload Metadata", color='#1976d2', classes=['tsk-btn'], on_click=lambda: query_endpoint_single(packet=meta_string.value, endpoint=schemas["put_endPoints"][task.value]))
                        if error_.value is not None:
                            solara.Warning(error_.value, icon=True)
                            
                        if response_records is not None:
                            print(response_records)
                            logfile = open('logs/upload_log.txt','w')
                            for record in response_records:
                                logfile.write(record+"\n")
                            logfile.close()
                            
                            solara.FileDownload(data=open(f'./logs/upload_log.txt', "rb"), filename=f'upload_log_at_{date_time_stamp}.txt', label=f'Get Logs')
                    


        # Register platforms,platform locations, with many sensors and parameters in bulk
        if (task_type == "bulk") & (task.value=="Register a new platform "):
            with solara.Card():
                solara.Markdown(md_text='Upload metadata with CSV files, Headers in the CSV file must conform to selected task')
                solara.Markdown(md_text='Download example templates with "Get Template Button"')
            with solara.Row():
                with solara.GridFixed(columns=3):
                    with solara.Card(title='Step 1: Register Platforms'):
                        solara.Markdown(md_text='Upload metadata for a list of platforms')
                        file_input_details(schemas["endpoint_schemas"][schemas["put_endPoints"][task.value]], task.value, on_file_platforms)
                        
                        if api_response is not None:
                            solara.Info(f'Response: {api_response}', text=True, icon=True)
                        
                        
                    with solara.Card(title='Step 2: Register Platform Locations'):
                        solara.Markdown(md_text='Upload metadata for a list of platform locations')
                        file_input_details(schemas["endpoint_schemas"][schemas["put_endPoints"]["Install a device at a location "]], "Install a device at a location", on_file_platform_location)
                        
                        if api_response is not None:
                            solara.Info(f'Response: {api_response}', text=True, icon=True)
                        
                        
                    with solara.Card(title='Step 3: Add Devices to Platforms'):
                        solara.Markdown(md_text='Upload metadata for a list of sensors attached to the registered platforms')
                        file_input_details(schemas["endpoint_schemas"][schemas["put_endPoints"]["Attach a new sensor to a platform "]], "Attach a new sensor to a platform", on_file_sensors)
                        
                        if api_response is not None:
                            solara.Info(f'Response: {api_response}', text=True, icon=True)
                        
                        
                    with solara.Card(title='Step 4: Register Device Locations'):
                        solara.Markdown(md_text='Upload metadata for a list of device locations (Must be same as platform)')
                        file_input_details(schemas["endpoint_schemas"][schemas["put_endPoints"]["Install a device at a location "]], "Install a device at a location", on_file_sensor_location)
                        
                        if api_response is not None:
                            solara.Info(f'Response: {api_response}', text=True, icon=True)
                        
                    with solara.Card(title='Step 5: Add device calibrations and maintenance history'):
                        solara.Markdown(md_text='Upload information on device calibration, download template via the link below')
                        file_input_details(schemas["endpoint_schemas"][schemas["put_endPoints"]["Update platform calibration "]], "Update platform calibration", on_file_calibration_location)

                        solara.Markdown(md_text='Upload information on maintenance history, download template via the link below')
                        file_input_details(schemas["endpoint_schemas"][schemas["put_endPoints"]["Update platform maintenance "]], "Update platform maintenance", on_file_maintenance_history)
                        
                        if api_response is not None:
                            solara.Info(f'Response: {api_response}', text=True, icon=True)
                        
                    with solara.Card(title='Step 6: Register Device Parameters'):
                        solara.Markdown(md_text='Upload metadata for a list of parameters and measurands for each attached sensors')
                        file_input_details(schemas["endpoint_schemas"][schemas["put_endPoints"]["Register a sensor parameter "]], "Register a sensor parameter", on_file_params)
                        
                        if api_response is not None:
                            solara.Info(f'Response: {api_response}', text=True, icon=True)
                        
                        
            use_endpoint_keys = ["Register a new platform ", "Install a device at a location ", "Attach a new sensor to a platform ","Install a device at a location ","Update platform calibration ", "Update platform maintenance ", "Register a sensor parameter "]

            meta_csv_data = [platform_content, platform_location_content, sensor_content, sensor_location_content, calibration_content, maintenance_content, param_content]
            
            with solara.Row(style={'padding-bottom':'30px'}):
                with solara.HBox():
                    solara.Button("Upload Metadata", color='#1976d2', classes=['tsk-btn'], on_click=lambda: bulk_upload(csv_data=meta_csv_data, endpoints_keys=use_endpoint_keys))
                    
                    if error_.value is not None:
                        solara.Warning(error_.value, icon=True)

                    if csv_check_info.value  is not None:
                        solara.Warning(csv_check_info.value, icon=True)
                        
                    if response_records is not None:
                        print(response_records)
                        logfile = open('logs/upload_log.txt','w')
                        for record in response_records:
                            logfile.write(record+"\n")
                        logfile.close()
                                
                        solara.FileDownload(data=open(f'./logs/upload_log.txt', "rb"), filename=f'upload_log_at_{date_time_stamp}.txt', label=f'Get Logs')
        
        # Bulk metadata update
        if (task_type == "bulk") & (task.value != "Attach a new sensor to a platform ") & (task.value!="Register a new platform "):
            with solara.Card():
                solara.Markdown(md_text='Headers in the CSV file must conform to selected task. Download template via the link below')
                
                temp_df = pd.DataFrame(task_schema, index=[0])
                if 'static_attributes' in temp_df.columns:
                    
                    temp_df['static_attributes'] = str(doubleQuoteDict(task_schema['static_attributes']))
            
                if 'notes' in temp_df.columns:
                    temp_df['notes'] = str(doubleQuoteDict(task_schema['notes']))
            
                if 'platform_communication_details' in temp_df.columns:
                    temp_df['platform_communication_details'] = str(doubleQuoteDict(task_schema['platform_communication_details']))
            
                if 'sensor_calibration_parameters' in temp_df.columns:
                    temp_df['sensor_calibration_parameters'] = str(doubleQuoteDict(task_schema['sensor_calibration_parameters']))

                solara.FileDownload(data=temp_df.to_csv(index=False), filename=f'template_for_{schemas["put_endPoints"][task.value]}.csv', label=f'Download {task.value} Template')
                solara.Markdown(md_text='Upload CSV file')
                solara.FileDrop(label='Drop CSV file here...',on_file=on_file ,lazy=True)
                if api_response is not None:
                    solara.Info(f'Response: {api_response}', text=True, icon=True)
            
                with solara.Row(style={'padding-bottom':'30px'}):
                    with solara.HBox():
                        solara.Button("Upload Metadata", color='#1976d2', classes=['tsk-btn'], on_click=lambda: query_endpoint_bulk(data=pd.read_csv(io.BytesIO(content)), endpoint=schemas["put_endPoints"][task.value]))

                        if error_.value is not None:
                            solara.Warning(error_.value, icon=True)
                            
                        if response_records is not None:
                            print(response_records)
                            logfile = open('logs/upload_log.txt','w')
                            for record in response_records:
                                logfile.write(record+"\n")
                            logfile.close()
                                    
                            solara.FileDownload(data=open(f'./logs/upload_log.txt', "rb"), filename=f'upload_log_at_{date_time_stamp}.txt', label=f'Get Logs')
                
Page()
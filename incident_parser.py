__author__ = "Simon Melotte"

import json
import os
import requests
from datetime import date
from datetime import timedelta

NUMBER_OF_DAYS = 10

                    
def getIncidents(base_url, token, deltaDays = 1):
    today = date.today()
    fromDate = today - timedelta(days = deltaDays)
    url = "https://%s/api/v1/audits/incidents?from=%s" % ( base_url, fromDate )

    headers = {"content-type": "application/json; charset=UTF-8", 'Authorization': 'Bearer ' + token }    
    response = requests.get(url, headers=headers)
    
    events = response.json()
    
    eventFile = open("events.log", "w")

    for event in events:
        for audit in event["audits"]:
            if (event['type'] == "container"):
                if ('user' in audit and 'namespace' in audit):
                    output(eventFile, """time="{}", type="{}", hostname="{}", containerName="{}", imageName="{}", user="{}", type="{}", attackType="{}", namespace="{}", msg="{}" """.format(audit['time'], event['type'], event['hostname'], event['containerName'], event['imageName'], audit['user'], audit['type'], audit['attackType'], audit['namespace'], audit['msg'] ,audit['attackType'] ) )
                elif ('user' in audit):
                    output(eventFile, """time="{}", type="{}", hostname="{}", containerName="{}", imageName="{}", user="{}", type="{}", attackType="{}", namespace="n/a", msg="{}" """.format(audit['time'], event['type'], event['hostname'], event['containerName'], event['imageName'], audit['user'], audit['type'], audit['attackType'], audit['msg'] ,audit['attackType'] ) )
                elif ('namespace' in audit):
                    output(eventFile, """time="{}", type="{}", hostname="{}", containerName="{}", imageName="{}", user="n/a", type="{}", attackType="{}", namespace="{}", msg="{}" """.format(audit['time'], event['type'], event['hostname'], event['containerName'], event['imageName'], audit['type'], audit['attackType'], audit['namespace'], audit['msg'] ,audit['attackType'] ) )
                else:                    
                    output("""time="{}", type="{}", hostname="{}", containerName="{}", imageName="{}", user="n/a", type="{}", attackType="{}", namespace="n/a", msg="{}" """.format(audit['time'], event['type'], event['hostname'], event['containerName'], event['imageName'], audit['type'], audit['attackType'], audit['msg'] ,audit['attackType'] ) )
            elif (event['type'] == "host"):
                if ('accountID' in audit ):
                    output(eventFile, """time="{}", type="{}", hostname="{}", category="{}", accountID="{}", user="{}", type="{}", attackType="{}", processPath="{}", msg="{}" """.format(audit['time'], event['type'], event['hostname'], event['category'], event['accountID'], audit['user'], audit['type'], audit['attackType'], audit['processPath'], audit['msg'] ,audit['attackType'] ) )
                else:
                    output(eventFile, """time="{}", type="{}", hostname="{}", category="{}", accountID="n/a", user="{}", type="{}", attackType="{}", processPath="{}", msg="{}" """.format(audit['time'], event['type'], event['hostname'], event['category'], audit['user'], audit['type'], audit['attackType'], audit['processPath'], audit['msg'] ,audit['attackType'] ) )   
   
    eventFile.close()            

def output(eventFile, myString):
    eventFile.write("""{}\n""".format(myString) )
    print ("""{}\n""".format(myString) )

def login(base_url, access_key, secret_key): 
    url = "https://%s/api/v1/authenticate" % ( base_url )

    payload = json.dumps({
        "username": access_key,
        "password": secret_key
    })
    headers = {"content-type": "application/json; charset=UTF-8"}    
    response = requests.post(url, headers=headers, data=payload)
    return response.json()["token"]

def getParamFromJson(config_file):
    f = open(config_file,)
    params = json.load(f)
    pcc_api_endpoint = params["pcc_api_endpoint"]
    access_key_id = params["access_key_id"]
    secret_key = params["secret_key"]
    # Closing file
    f.close()
    return pcc_api_endpoint, access_key_id, secret_key;

def main():    
    global NUMBER_OF_DAYS
    CONFIG_FILE= os.environ['HOME'] + "/.prismacloud/credentials.json"
    PCC_API_ENDPOINT, ACCESS_KEY_ID, SECRET_KEY = getParamFromJson(CONFIG_FILE)
    token = login(PCC_API_ENDPOINT, ACCESS_KEY_ID, SECRET_KEY)
    getIncidents(PCC_API_ENDPOINT, token, NUMBER_OF_DAYS)

if __name__ == "__main__":
    main()
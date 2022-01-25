# How to use this script

## Authentication

Create an access key from Settings then Access key  
Get the path to console from Compute tab, System, Utilities  

Create a file into home directory .prismacloud/credentials.json with the following structure  

```json
{
  "pcc_api_endpoint": "__REDACTED__",
  "access_key_id": "__REDACTED__",
  "secret_key": "__REDACTED__"
}
```

## Run the script

```console
python3 incident_parser.py
```

It should generate a log file with all the incidents happening in the last x days.
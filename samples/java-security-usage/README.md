# Description
This sample is a Java back-end application running on the Cloud Foundry. On incoming requests it checks whether the user is authorized using the [Java Security](../../core/) library.

# Deployment on Cloud Foundry
To deploy the application, the following steps are required:
- Compile the Java application
- Create a xsuaa service instance
- Configure the manifest
- Deploy the application
- Access the application

## Compile the Java application
Run maven to package the application
```shell
mvn clean package
```

## Create the xsuaa service instance
Use the [xs-security.json](./xs-security.json) to define the authentication settings and create a service instance
```shell
cf create-service xsuaa application xsuaa-java-security -c xs-security.json
```

## Configure the manifest
The [vars](../vars.yml) contains hosts and paths that need to be adopted.

## Deploy the application
Deploy the application using cf push. It will expect 1 GB of free memory quota.

```shell
cf push --vars-file ../vars.yml
```

## Access the application
- Get an client-credentials access token via `curl. You can get the information to fill the placeholders from your system environment `cf env java-security-usage`:

```
curl -X POST \
  h<<VCAP_SERVICES.xsuaa.credentials.url>>/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'client_id=<<VCAP_SERVICES.xsuaa.credentials.clientid>>&client_secret=<<VCAP_SERVICES.xsuaa.credentials.clientsecret>>&grant_type=client_credentials'
```

Copy the `access_token` into your clipboard.

- Access the app via `curl`. Don't forget to fill the placeholders.
```
curl -X GET \
  https://java-security-usage-<<ID>>.<<LANDSCAPE_APPS_DOMAIN>>/hello-java-security \
  -H 'Authorization: Bearer <<your access_token>>'
```

You should see something like this:
```
You ('<your user>') can access the application with the following scopes: '<your scopes>'.
```

## Clean-Up
Finally delete your application and your service instances using the following commands:
```
cf delete -f java-security-usage
cf delete-service -f xsuaa-java-security
```
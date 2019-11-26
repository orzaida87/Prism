import datetime
import requests
import ssl
import OpenSSL
import socket
import csv
import boto3


local_profiles = {'prod', 'dev'}
client = boto3.client('route53')

dump = [['Host', 'Issuer', 'Start', 'End', 'Expired', 'Subject']]

def rchop(string, ending):
  if string.endswith(ending):
    return string[:-len(ending)]
  return string

def cert_check(hostname):
    hostname = rchop(hostname, ".")
    print(hostname)
    port = 443
    row = []
    row.append(hostname)
    try:
        socket.setdefaulttimeout(1)
        cert = ssl.get_server_certificate(
            (hostname, port), ssl_version=ssl.PROTOCOL_TLSv1)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    except (ValueError, socket.error, socket.gaierror, socket.herror, socket.timeout):
        row.append("No Avilable Certificate Or Endpoint Public Access")
        return row

    try:
        row.append(x509.get_issuer())
        row.append(x509.get_notBefore().decode())
        row.append(x509.get_notAfter().decode())
        row.append(x509.has_expired())
        row.append(x509.get_subject())
    except:
        row.append("No Avilable Certificate Or Endpoint Public Access")
        return row

    return row

for profile in local_profiles:
    session = boto3.Session(profile_name=profile)
    client = session.client('route53')
    zones = client.list_hosted_zones()

    for zone in zones['HostedZones']:

        if zone['Config']['PrivateZone'] != True:
            records = client.list_resource_record_sets(HostedZoneId=zone['Id'])
            for record in records['ResourceRecordSets']:
                if record['Type'] in ['SOA', 'MX', 'NS', 'TXT', 'SRV']:
                    continue
                dump.append(cert_check(record['Name']))


response = requests.get(
            'https://api.godaddy.com/v1/domains?statuses=ACTIVE',
            headers={'Authorization': 'sso-key AQMzhxnWZoK_B3G7r8n7as6SSbbnxWUQCm:4NEnDNfLVjySJ7x5hdSwr6'},)

for domain in response.json():
    url = 'https://api.godaddy.com/v1/domains/' + domain['domain'] + '/records'
    response = requests.get(
            url,
            headers={'Authorization': 'sso-key AQMzhxnWZoK_B3G7r8n7as6SSbbnxWUQCm:4NEnDNfLVjySJ7x5hdSwr6'},)
    if 'code' in response.json():
        continue
    for record in response.json():
        if record['type'] in ['SOA', 'MX', 'NS', 'TXT', 'SRV']:
            continue
        if record['name'] in ['@']:
            fqdn = domain['domain']
            dump.append(cert_check(fqdn))
            continue
        try:
            fqdn = record['name'] + "." + domain['domain']
        except:
            fqdn = domain['domain']
        dump.append(cert_check(fqdn))

with open('cert_report.csv', 'w') as csvFile:
    writer = csv.writer(csvFile)
    writer.writerows(dump)

csvFile.close()

# Setup-Auto-Update-Architecture-for-Global-Deployment-Version-2
A fully automated script to fetch Zabbix templates, external scripts, and Grafana dashboards from GitHub, then deploy them to your local Zabbix and Grafana environments. Supports .xml, .json, and .yaml template formats and handles automatic format detection and overwriting of existing templates.  
It is the version 3  

# Prerequisite
1). Zabbix Installed on the Server.

2). Grafana Installed on the Server.

3). Edit the auto_update_config_v2.json and Give the : 

    i.  "category": "Websites,Infrastructure,Databases" : Specify the category you want to install 

    ii. zabbix url 
       
       if zabbix is Installed with apache2 then url will be :

          http://34.130.10.46/zabbix/api_jsonrpc.php

       else with nginx : 
          
          http://34.130.10.46/api_jsonrpc.php

    iii. username and password

    iv. grafana url

    v.  grafana api key generate (Grafana icon --> Administration --> Users and access --> Service accounts --> Add Service Account --> Create service account --> Enter the Display name and Role : Editor or Admin --> Add 
         service account token --> Expiration : No expiration --> Generate token --> Copy the Token)

    vi. Git Repo url (Code --> HTTPS --> copy the url)


# On the Server install Git 
    sudo apt install git
# And run this Comamnd for first time 

    git clone https://github.com/pillai-vivek/Setup-Auto-Update-Architecture-for-Global-Deployment-Version-3.git && cd Setup-Auto-Update-Architecture-for-Global-Deployment-Version-3 && chmod +x run.sh && ./run.sh

# And run this Comamnd after first time

    cd "$(find / -type d -name 'Setup-Auto-Update-Architecture-for-Global-Deployment-Version-3' 2>/dev/null | head -n 1)" && chmod +x run.sh && ./run.sh

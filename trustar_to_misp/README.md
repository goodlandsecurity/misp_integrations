# trustar_to_misp

**Author:** [@th3_jiv3r](https://twitter.com/th3_jiv3r)  
#
This integration will scrape the TruStar API to pull reports from the RH-ISAC enclave.  

 TruStar reports are formatted into MISP json standard and make API calls to MISP via PyMISP to create a MISP event for each TruStar report found.  
#
#### Recommended to use this with your Python virtual environment.  
#
#### Recommended to set the MISP configuration in keys.py and the TruStar configuration in trustar.conf  

  *MISP - URL, API key, certificate verification, and client certificate (if preferred)*  
  *TruStar - Auth endpoint, API endpoint, API key, API secret*  
#
#### Recommended to put the files from this repo into /var/www/MISP/PyMISP/examples/  
#
  **ex.**
```sh  
$ cp ~/misp_integrations/trustar_to_misp/trustar_misp.py /var/www/MISP/PyMISP/examples/trustar_misp.py
  
$ cp ~/misp_integrations/trustar_to_misp/keys.py /var/www/MISP/PyMISP/examples/keys.py
  
$ cp ~/misp_integrations/trustar_to_misp/trustar.conf /var/www/MISP/PyMISP/examples/trustar.conf
```
#
#### Recommended to run as a cronjob and scrape reports from TruStar to populate into MISP *(Example shows running once every 4 hours)*  
#
  **ex.** 
  
```sh
$ 0 */4 * * * */var/www/MISP/venv/bin/python3 /var/www/MISP/PyMISP/examples/trustar_misp.py
```
#

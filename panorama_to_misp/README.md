# panorama_to_misp

**Author:** [@th3_jiv3r](https://twitter.com/th3_jiv3r)  

This integration will scrape the Panorama API to pull the top threats report for the last day (00:00:00-23:59:59).  

Top threats report will be formatted in MISP json format and an event will be created listing each threat as an attribute and list the count in the attribute's comment field.  

#### Recommended to use this with your Python virtual environment.  
  
#### Recommended to set the MISP configuration in keys.py 

  *MISP - URL, API key, certificate verification, and client certificate (if preferred)*  
  
#### Recommended to put the file from this repo into /var/www/MISP/PyMISP/examples/  

  **ex.** *cp ~/misp_integrations/panorama_to_misp/pan_misp.py /var/www/MISP/PyMISP/examples/*  
  
#### Recommended to run as a cronjob and query for top threats report to populate into MISP *(Example shows running at 0400 every day)*  

  **ex.** 0 4 * * * */var/www/MISP/venv/bin/python3 /var/www/MISP/PyMISP/examples/trustar_misp.py*  
 

# How to Get a WHOIS API Key and Use It in Reco

To use the WHOIS feature in Reco, you need an **API key** from a WHOIS API provider. Follow these steps:

---

## 1. Sign Up for an API Key
1. Go to a WHOIS API provider website such as:
   - [WhoisJson](https://whoisjson.com)  
   - [WhoisXML API](https://whoisxmlapi.com)  
   - [API Ninjas WHOIS](https://api-ninjas.com/api/whois)  

2. Register for a free account (you’ll need your email try [temp mail](https://temp-mail.org/).  

3. After logging in, go to your **Dashboard** or **API Keys** page.  

4. Copy your API key (it will look like a long string, for example:  
    abcd1234efgh5678
yaml
Copy code

---

## 2. Add the API Key to the Code
1. Open the file `whois.go` (the containing the `whoIs` function).  

2. Find this line near the top of the function:  

```go
api := "PASTE_YOUR_API"
```
Replace **PASTE_YOUR_API** with the key you copied. 

3. Save and Run
Save the file.

Rebuild and run the program with:

bash
Copy code
go run .

Now the WHOIS lookups should work using your personal API key.

4. Changing the Key Later
If you ever need to replace your API key:

Open the same file again.

Change the string inside api := "...".

Save the file and re-run the program.

# 🚦 RedirectFuzzer

A Python tool for testing Open Redirect vulnerabilities.

**Author:** Ozan Turan Çakır

⚠️ Use this tool only in authorized testing environments.


![RedirectFuzzer Kullanım Ekran Görüntüsü](images/help.png)



## Usage
```bash
python3 RedirectFuzzer.py -i urls.txt --payload-file targetdomains.txt -o results.csv




## ⚙️ Requirements

To run RedirectFuzzer, you need Python 3.8 or newer and the following libraries:

* Python 3.8+
* `requests`
* `termcolor`
* `pyfiglet`

You can install the Python dependencies using the `requirements.txt` file:

```bash
pip3 install -r requirements.txt

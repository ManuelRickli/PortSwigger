##### PortSwigger BurpSuite Certification Summary
# Business Logic Vulnerabilities
It is very hard to define such vulnerabilities, since they are unique to the logic of the application. Examples of exploits are:
  * The app trusts client-side validation --> alter critical information in a proxy:
	* Usernames
	* Prices
    * Quantities
	* etc.
  * Unconventional input is wrongly handled:
	* Negative numbers
	* Very large numbers
    * Repeated requests in case of numerical limits on a single one
	* Very long strings

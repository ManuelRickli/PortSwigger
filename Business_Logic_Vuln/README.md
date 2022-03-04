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

It can be beneficial to try to delete user input forms, such as the original password field in the change password POST request. All permutations should be tried and the respective output observed for irregularities.

Another logic flaw can arise in the sequence of actions and how they are handled. Trying out different orders of sequences or multiple calls of the same request might result in unexpected behaviour that benefits the attacker. This is also true for dropping packets.

Alternating coupons is a method that should be tried. It can be possible to acquire more than one.

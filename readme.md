# CVSSlib

An (over-engineered) library that supports calculating values from CVSS2 and CVSS3 vectors.

It's pretty simple to use:

    from cvsslib import cvss2, cvss3, parse_vector
    
    vector_v2 = "AV:L/AC:M/Au:S/C:N/I:P/A:C/E:U/RL:OF/RC:UR/CDP:N/TD:L/CR:H/IR:H/AR:H"
    parse_vector(vector_v2, cvss2)
    >> (5, 3.5, 1.2)
    
    vector_v3 = "CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/MPR:N"
    parse_vector(vector_v3, cvss3)
    >> (5.8, 5.8, 7.1)

You can access every CVSS enum through the `cvss2` or `cvss3` modules:

    from cvsslib import cvss2
    
    value = cvss2.ReportConfidence.CONFIRMED
    
    if value != cvss2.ReportConfidence.NOT_DEFINED:
        do_something()
        
        
There are some powerful mixin functions if you need a class with CVSS members:

    from cvsslib import cvss2, class_mixin
    
    base = class_mixin(cvss2)  # Can pass cvss3 module instead
    
    class SomeObject(base):
        def print_stats(self):
            for item, value in self._enums.items():
                print("{0} is {1}".format(item, value)
     
    state = SomeObject()
    state.print_stats()
    print(state.calculate())
    
    # Access members:
    if state.report_confidence == ReportConfidence.NOT_DEFINED:
        do_something()
    

It also supports Django models using a metaclass

    from cvsslib import cvss2, django_mixin
    from django.db import models
    
    metaclass = django_mixin(cvss2)
    
    class CVSSModel(models.Model, metaclass=metaclass)
        pass
        
    # CVSSModel now has lots of DecimalFields you can use
    x = CVSSModel()
    x.save()
    x.exploitability
 
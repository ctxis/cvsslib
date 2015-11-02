# CVSSlib [![Build Status](https://travis-ci.org/ctxis/cvsslib.svg?branch=master)](https://travis-ci.org/ctxis/cvsslib)

An (over-engineered) library that supports calculating values from CVSS2 and CVSS3 vectors.

It's pretty simple to use:

```python
from cvsslib import cvss2, cvss3, parse_vector

vector_v2 = "AV:L/AC:M/Au:S/C:N/I:P/A:C/E:U/RL:OF/RC:UR/CDP:N/TD:L/CR:H/IR:H/AR:H"
parse_vector(vector_v2, cvss2)
>> (5, 3.5, 1.2)

vector_v3 = "CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/MPR:N"
parse_vector(vector_v3, cvss3)
>> (5.8, 5.8, 7.1)
```

You can access every CVSS enum through the `cvss2` or `cvss3` modules:

```python
from cvsslib import cvss2

value = cvss2.ReportConfidence.CONFIRMED

if value != cvss2.ReportConfidence.NOT_DEFINED:
    do_something()
```  
        
There are some powerful mixin functions if you need a class with CVSS members:

```python
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
```

It also supports Django models:

```python
from cvsslib.contrib.django_model import CVSS2Model

class CVSSModel(CVSS2Model)
    pass
    
# CVSSModel now has lots of DecimalFields you can use
x = CVSSModel()
x.save()
x.exploitability
```
 
And there is a command line tool available:
 
```python
> cvss CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:N/I:H/A:N/E:P/RL:U/RC:U/CR:H/IR:L/AR:H/MAV:L/MUI:R/MS:C/MC:N/MI:L/MA:N
Base Score:     5.3
Temporal:       4.6
Environment:    1.3
 ```
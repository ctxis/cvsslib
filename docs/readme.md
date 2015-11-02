# Code

I've had the misfortune of having to write several CVSS libraries in Python, this is my latest attempt at one that is tested and re-usable. Due to the nature of the CVSS v2 and v3 specifications (terrible 'reference code', huge amount of state and fiddly maths + corner cases) the current open source Python libraries for manipulating cvss are somewhat terrible and unmaintained. The only current implementation of v3 [has a (broken) 300 line function full of conditionals to handle vectors](https://github.com/toolswatch/pycvss3/blob/master/lib/pycvss3.py#L36), and while [some that implement v2](https://github.com/esn89/cvss-v2-calc) have better code quality they still lack tests and an importable API.

There is also a lack of a useful reference implementation. There is an official calculator for v2 and v3, but these are useless for automated testing. The v3 is all in JavaScript (and unpublished I might add, so you have to dig through the undocumented page JS), and you would need to screen-scrape the NIST website to automate the v2 calculator. Eww.

This library has [30 cvss v2 and v3 vectors](https://github.com/ctxis/cvsslib/blob/master/tests/cvss_scores.py) and their official results to test against. More can be added really easily.

## Design

In the authors experience the large number of CVSS variables that go into the complex calculations leads to messy code with lots of duplication, which is a fantastic place for bugs to hide. `cvsslib` makes heavy use of Python magic to remove as much duplication as possible, allowing it to handle both v2 and v3 calculations with the same API. The core of this is inspired by pytest fixtures and is used in the calculations file of each CVSS versions module. Here is v2's `exploitability` function:

```python
def calculate_exploitability(access: AccessVector,
                             complexity: AccessComplexity,
                             auth: Authentication):
    # Exploitability = 20* AccessVector*AccessComplexity*Authentication
    return D("20") * access * complexity * auth
```

Each calculation function expresses the enums it needs to do it's calculation as parameter annotations. These values of these are injected by a function called `run_calculation`:

```python
def calculate_base_score(run_calculation, impact_function):
    # BaseScore = round_to_1_decimal(((0.6*Impact)+(0.4*Exploitability)-1.5)*f(Impact))
    # f(impact)= 0 if Impact=0, 1.176 otherwise
    impact = run_calculation(impact_function)
    exploitability = run_calculation(calculate_exploitability)

    result = (D("0.6") * impact) + (D("0.4") * exploitability) - D("1.5")
    f_impact = 0 if impact == 0 else D("1.176")

    return round(result * f_impact, 1)
```

There are two alternatives to this: pass each attribute as a normal parameter ([leads to tonnes of parameters](https://github.com/toolswatch/pycvss3/blob/master/lib/formulas.py#L104) and is brittle) or passing a single object around (which is still tied to the attribute name). This way only the enum class is specified, which means it's decoupled from the code that actually gets the value.

Enums are just normal Python enums:

```python
class AvailabilityRequirement(BaseEnum):
    """
    Vector: AR
    """
    LOW = D("0.5")
    MEDIUM = D("1.0")
    HIGH = D("1.51")
    NOT_DEFINED = NotDefined(D("1.0"))
```

It's necessary to wrap NOT_DEFINED in a NotDefined instance, because otherwise the value ("1.0") clashes with MEDIUM and this causes issues.

To make a Django model or a normal Python class filled with cvss v2 or v3 attributes (plus functions to calculate, update etc) we make use of a metaclass. There is a function called `class_mixin` that takes a CVSS module and returns a base class you can use. This looks at all the Enums defined within the module and does some magic to dynamically add those attributes to a class and hook up some utility functions.


## Guides

  - https://www.first.org/cvss/v2/guide
  - https://www.first.org/cvss/specification-document

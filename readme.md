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

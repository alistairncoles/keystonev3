keystonev3
==========

example usage:

# to setup a fourth account in test-domain for functional tests:
keystonev3.py setup-func-test-env  --os-endpoint http://u132.localdomain:5000/v3

# to setup two users and projects in a specified domain:
keystonev3.py setup-test-env  --os-endpoint http://u132.localdomain:5000/v3 --os-domain my-domain-name

# to list all users (with their domain menbership)
keystonev3.py user-list  --os-endpoint http://u132.localdomain:5000/v3

# to list all projects (with their domain menbership)
keystonev3.py project-list  --os-endpoint http://u132.localdomain:5000/v3

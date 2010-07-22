#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ここは解説です

デモコードdえす

.. code-block:: python

  #!/usr/bin/env python
  from openravepy import *
  import numpy as np
  env = Environment()
  env.SetViewer('qtcoin')
  body = env.ReadKinBodyXMLFile(filename='data/mug1.kinbody.xml')
  env.AddKinBody(body)
  body.SetTransform(np.eye(4))

.. image:: ../../images/examples_tutorial0_mug_readkinbody.png
  :height: 200

"""
from openravepy import __build_doc__
if not __build_doc__:
    from openravepy import *
else:
    from openravepy import OpenRAVEModel
from numpy import eye
def run():
    env = Environment()
    env.SetViewer('qtcoin')
    body = env.ReadKinBodyXMLFile(filename='data/mug1.kinbody.xml')
    env.AddKinBody(body)
    body.SetTransform(eye(4))

if __name__ == "__main__":
    run()

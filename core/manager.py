import os
import sys
import glob

# Adds rules to path variable and returns list of rules names
def get_rules(role):
  rules = []
  
  # Returns list of paths that match specified pattern
  for r in glob.glob('rules/**/'):
    # Iterate list and add to path variable 
    sys.path.insert(0, r)  
  
  if role == 'attacker':    
    for r in glob.glob('rules/**/rule_*.py', recursive=True):      
      fname = os.path.basename(r.split('.')[0])
      rules.append(fname)
      
  return rules

# Import all rules moduless in runtime    
def rule_manager(role):
  all_rules = get_rules(role)
  loaded_rules = {}
  
  for r in all_rules:
    mod = __import__(r)
    # Call "Rule()" class of "r" python script
    loaded_rules[r] = mod.Rule()

  return loaded_rules

import os
import sys
import glob

def get_rules(role):
  rules = []
  
  for r in glob.glob('rules/**/'):
    sys.path.insert(0, r)  
  
  if role == 'attacker':    
    for r in glob.glob('rules/**/rule_*.py', recursive=True):      
      fname = os.path.basename(r.split('.')[0])
      rules.append(fname)
      
  return rules
    
def rule_manager(role):
  all_rules = get_rules(role)
  loaded_rules = {}
  
  for r in all_rules:
    mod = __import__(r)
    loaded_rules[r] = mod.Rule()

  return loaded_rules

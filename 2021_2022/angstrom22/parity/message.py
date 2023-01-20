#!/usr/bin/env python3
from z3 import *
from pprint import pprint

inpl = 40
x = [BitVec(f'x[{i}]',64) for i in range(inpl)]
s = Solver()

constraints = []

def all_smt(s, initial_terms):
    def block_term(s, m, t):
        s.add(t != m.eval(t))
    def fix_term(s, m, t):
        s.add(t == m.eval(t))
    def all_smt_rec(terms):
        if sat == s.check():
           m = s.model()
           yield m
           for i in range(len(terms)):
               s.push()
               block_term(s, m, terms[i])
               for j in range(i):
                   fix_term(s, m, terms[j])
               for m in all_smt_rec(terms[i:]):
                   yield m
               s.pop()
    for m in all_smt_rec(list(initial_terms)):
        yield m

def get_models(constraints:list, num_models: int, var_list=None) -> list:
    """
    :constraints:
        list of constraints to solve
    :num_models:
        max number of models to get (would terminate at the max possible
        number of models if not possible)
    :var_list:
        list of z3 variables to monitor in the models
        if passed a list, the return value would be list of integers
        in the order as presented in var_list
    :return:
        if `var_list` is passed, list of integers
        otherwise, list of models
    """
    models, results = [], []
    solver = Solver()
    solver.add(constraints)
    solver.push()  #push the current state (of added constraints)
    while len(models) < num_models and solver.check() == sat:
        try:
            model = solver.model()
            if var_list:
                result = [model[var].as_long() for var in var_list]
                print(result)
                results.append(result)
            models.append(model)
            block = []
            for declaration in model:
                c = declaration()
                block.append(c != model[declaration])
            solver.add(Or(block))
            solver.push() # save some work, dont redo the work done so far
        except KeyboardInterrupt: # got bored waiting?
            print("interrupted")
            break
    if var_list:
        return results
    return models

m = get_models(constraints, 2)
pprint(m)


'''
import itertools
from z3 import *

def models(formula, max=10):
    " a generator of up to max models "
    solver = Solver()
    solver.add(formula)

    count = 0
    while count<max or max==0:
        count += 1

        if solver.check() == sat:
            model = solver.model()
            yield model

            # exclude this model
            block = []
            for z3_decl in model: # FuncDeclRef
                arg_domains = []
                for i in range(z3_decl.arity()):
                    domain, arg_domain = z3_decl.domain(i), []
                    for j in range(domain.num_constructors()):
                        arg_domain.append( domain.constructor(j) () )
                    arg_domains.append(arg_domain)
                for args in itertools.product(*arg_domains):
                    block.append(z3_decl(*args) != model.eval(z3_decl(*args)))
            solver.add(Or(block))

x, y = Ints('x y')
F = [x >= 0, x <= 1, y >= 0, y <= 2, y == 2*x]
for m in models(F):
    print(m)
'''
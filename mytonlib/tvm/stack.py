#!/usr/bin/env python3
# -*- coding: utf_8 -*-

def get_from_tvm_list(stack, index, remove=True):
	stack_len = len(stack)
	need_index = stack_len - index - 1
	if need_index < 0:
		raise Exception(f"get_from_tvm_list error: need_index < 0 (stack_len: {stack_len}, index: {index})")
	result = stack[need_index]
	if remove is True:
		stack.pop(need_index)
	return result
#end define

def swap_items_in_tvm_list(stack, index1, index2):
	stack_len = len(stack)
	need_index1 = stack_len - index1 - 1
	need_index2 = stack_len - index2 - 1
	stack[need_index1], stack[need_index2] = stack[need_index2], stack[need_index1]
#end define

undefined8 FUN_140024fb0(longlong param_1,undefined8 *param_2)

{
  longlong *plVar1;
  undefined8 local_18 [2];
  
  plVar1 = FUN_140028680(*(longlong **)(*(longlong *)(*(longlong *)(param_1 + 0x10) + -8) + 8),
                         local_18,param_2);
  *(longlong *)(param_1 + 0x20) = *plVar1 + 0x40;
  return CONCAT71((int7)((ulonglong)plVar1 >> 8),1);
}


// FUNCTION_END

// FUNCTION_START: FUN_140024ff0 @ 140024ff0
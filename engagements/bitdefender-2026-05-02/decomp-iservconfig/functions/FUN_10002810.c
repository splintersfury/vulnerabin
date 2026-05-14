undefined4 __thiscall FUN_10002810(void *this,ushort param_1,wchar_t param_2)

{
  ushort uVar1;
  undefined2 extraout_var;
  
  uVar1 = __Getwctype(param_2,(_Ctypevec *)((int)this + 8));
  return CONCAT31((int3)(CONCAT22(extraout_var,uVar1) >> 8),(param_1 & uVar1) != 0);
}


// FUNCTION_END

// FUNCTION_START: FUN_10002830 @ 10002830
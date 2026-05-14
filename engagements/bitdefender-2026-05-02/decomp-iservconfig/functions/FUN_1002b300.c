void __thiscall FUN_1002b300(void *this,int param_1,int param_2,int param_3)

{
  void *pvVar1;
  code *pcVar2;
  void *pvVar3;
  
                    /* WARNING: Load size is inaccurate */
  if (*this != (int *)0x0) {
    FUN_1002b510(*this,*(int **)((int)this + 4));
                    /* WARNING: Load size is inaccurate */
    pvVar1 = *this;
    pvVar3 = pvVar1;
    if ((0xfff < (uint)(((*(int *)((int)this + 8) - (int)pvVar1) / 0x18) * 0x18)) &&
       (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3)))) {
      FUN_10032f7f();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    FUN_1002e346(pvVar3);
  }
  *(int *)this = param_1;
  *(int *)((int)this + 4) = param_1 + param_2 * 0x18;
  *(int *)((int)this + 8) = param_1 + param_3 * 0x18;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002b390 @ 1002b390
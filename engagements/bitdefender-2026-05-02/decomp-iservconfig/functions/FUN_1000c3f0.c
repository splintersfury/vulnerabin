undefined4 * __thiscall FUN_1000c3f0(void *this,byte param_1)

{
  int *piVar1;
  
  piVar1 = (int *)((int)this + 0x48);
  *(undefined ***)this = ProductInfo::vftable;
  FUN_10018dd0(piVar1,*(int **)(*piVar1 + 4));
  FUN_1002e346((void *)*piVar1);
  FUN_10018dd0((undefined4 *)((int)this + 0x40),*(int **)(*(int *)((int)this + 0x40) + 4));
  FUN_1002e346(*(void **)((int)this + 0x40));
  FUN_10018dd0((undefined4 *)((int)this + 0x38),*(int **)(*(int *)((int)this + 0x38) + 4));
  FUN_1002e346(*(void **)((int)this + 0x38));
  __Mtx_destroy_in_situ((int)this + 4);
  if ((param_1 & 1) != 0) {
    FUN_1002e346(this);
  }
  return (undefined4 *)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000c480 @ 1000c480
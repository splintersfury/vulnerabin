void __thiscall FUN_10005410(void *this,uint param_1,char param_2)

{
  uint *puVar1;
  uint uVar2;
  uint _Size;
  
  uVar2 = *(uint *)((int)this + 0x10);
  puVar1 = (uint *)((int)this + 0x10);
  if (param_1 <= uVar2) {
    if (0xf < *(uint *)((int)this + 0x14)) {
                    /* WARNING: Load size is inaccurate */
      this = *this;
    }
    *puVar1 = param_1;
    *(undefined1 *)((int)this + param_1) = 0;
    return;
  }
  _Size = param_1 - uVar2;
  if (_Size <= *(int *)((int)this + 0x14) - uVar2) {
    *puVar1 = param_1;
    if (0xf < *(uint *)((int)this + 0x14)) {
                    /* WARNING: Load size is inaccurate */
      this = *this;
    }
    _memset((void *)((int)this + uVar2),(int)param_2,_Size);
    *(undefined1 *)((int)((int)this + uVar2) + _Size) = 0;
    return;
  }
  param_1 = param_1 & 0xffffff00;
  FUN_10006150(this,_Size,param_1,_Size,param_2);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10005490 @ 10005490
void __thiscall FUN_100125f0(void *this,char *param_1)

{
  int iVar1;
  uint uVar2;
  int local_10 [3];
  
  uVar2 = *(uint *)((int)this + 0xc);
                    /* WARNING: Load size is inaccurate */
  if (((int)uVar2 < 0) && (uVar2 != 0)) {
    iVar1 = -((~uVar2 >> 5) * 4 + 4);
  }
  else {
    iVar1 = (uVar2 >> 5) * 4;
  }
  FUN_10013db0(this,local_10,uVar2 & 0x1f,param_1,*this + iVar1,uVar2 & 0x1f);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10012650 @ 10012650
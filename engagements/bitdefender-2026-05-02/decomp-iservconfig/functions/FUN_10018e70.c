void __thiscall FUN_10018e70(void *this,uint param_1,uint *param_2)

{
  uint *_Dst;
  code *pcVar1;
  uint uVar2;
  void *pvVar3;
  void *pvVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  uint *puVar9;
  
  uVar2 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  if (param_1 < 0x40000000) {
                    /* WARNING: Load size is inaccurate */
    iVar5 = *(int *)((int)this + 4) - *this >> 2;
                    /* WARNING: Load size is inaccurate */
    uVar6 = *(int *)((int)this + 8) - *this >> 2;
    if ((uVar6 <= 0x3fffffff - (uVar6 >> 1)) &&
       ((uVar6 = (uVar6 >> 1) + uVar6, uVar8 = param_1, uVar6 < param_1 ||
        (uVar8 = uVar6, uVar6 < 0x40000000)))) {
      uVar6 = uVar8 * 4;
      if (uVar6 < 0x1000) {
        if (uVar6 == 0) {
          puVar9 = (uint *)0x0;
        }
        else {
          puVar9 = (uint *)operator_new(uVar6);
        }
      }
      else {
        if (uVar6 + 0x23 <= uVar6) goto LAB_10018fd8;
        pvVar3 = operator_new(uVar6 + 0x23);
        if (pvVar3 == (void *)0x0) goto LAB_10018fe2;
        puVar9 = (uint *)((int)pvVar3 + 0x23U & 0xffffffe0);
        puVar9[-1] = (uint)pvVar3;
      }
      iVar7 = param_1 - iVar5;
      _Dst = puVar9 + iVar5;
      if (*param_2 == 0) {
        _memset(_Dst,0,iVar7 * 4);
      }
      else {
        for (; iVar7 != 0; iVar7 = iVar7 + -1) {
          *_Dst = *param_2;
          _Dst = _Dst + 1;
        }
      }
                    /* WARNING: Load size is inaccurate */
      FUN_100301d0(puVar9,*this,*(int *)((int)this + 4) - (int)*this);
                    /* WARNING: Load size is inaccurate */
      pvVar3 = *this;
      if (pvVar3 == (void *)0x0) {
LAB_10018fb4:
        *(uint **)this = puVar9;
        *(uint **)((int)this + 4) = puVar9 + param_1;
        *(uint **)((int)this + 8) = puVar9 + uVar8;
        FUN_1002e315(uVar2 ^ (uint)&stack0xfffffffc);
        return;
      }
      pvVar4 = pvVar3;
      if (((*(int *)((int)this + 8) - (int)pvVar3 & 0xfffffffcU) < 0x1000) ||
         (pvVar4 = *(void **)((int)pvVar3 + -4), (uint)((int)pvVar3 + (-4 - (int)pvVar4)) < 0x20)) {
        FUN_1002e346(pvVar4);
        goto LAB_10018fb4;
      }
      goto LAB_10018fe2;
    }
LAB_10018fd8:
    FUN_10001fb0();
  }
  FUN_10017fa0();
LAB_10018fe2:
  FUN_10032f7f();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10018ff0 @ 10018ff0
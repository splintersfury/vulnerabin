uint * __thiscall FUN_1001a820(void *this,uint *param_1,uint *param_2)

{
  uint uVar1;
  uint *puVar2;
  int iVar3;
  uint *puVar4;
  code *pcVar5;
  int iVar6;
  void *pvVar7;
  void *pvVar8;
  uint uVar9;
  uint uVar10;
  uint *puVar11;
  
                    /* WARNING: Load size is inaccurate */
  iVar3 = *this;
  iVar6 = *(int *)((int)this + 4) - iVar3 >> 2;
  if (iVar6 != 0x3fffffff) {
    uVar1 = iVar6 + 1;
    uVar9 = *(int *)((int)this + 8) - iVar3 >> 2;
    if (uVar9 <= 0x3fffffff - (uVar9 >> 1)) {
      uVar9 = (uVar9 >> 1) + uVar9;
      uVar10 = uVar1;
      if (uVar1 <= uVar9) {
        uVar10 = uVar9;
      }
      if (uVar10 < 0x40000000) {
        uVar9 = uVar10 * 4;
        if (uVar9 < 0x1000) {
          if (uVar9 == 0) {
            puVar11 = (uint *)0x0;
          }
          else {
            puVar11 = (uint *)operator_new(uVar9);
          }
        }
        else {
          if (uVar9 + 0x23 <= uVar9) goto LAB_1001a967;
          pvVar7 = operator_new(uVar9 + 0x23);
          if (pvVar7 == (void *)0x0) goto LAB_1001a971;
          puVar11 = (uint *)((int)pvVar7 + 0x23U & 0xffffffe0);
          puVar11[-1] = (uint)pvVar7;
        }
        puVar2 = puVar11 + ((int)param_1 - iVar3 >> 2);
        *puVar2 = *param_2;
                    /* WARNING: Load size is inaccurate */
        puVar4 = *this;
        if (param_1 == *(uint **)((int)this + 4)) {
          FUN_100301d0(puVar11,puVar4,(int)*(uint **)((int)this + 4) - (int)puVar4);
        }
        else {
          FUN_100301d0(puVar11,puVar4,(int)param_1 - (int)puVar4);
          FUN_100301d0(puVar2 + 1,param_1,*(int *)((int)this + 4) - (int)param_1);
        }
                    /* WARNING: Load size is inaccurate */
        pvVar7 = *this;
        if (pvVar7 == (void *)0x0) {
LAB_1001a94a:
          *(uint **)this = puVar11;
          *(uint **)((int)this + 4) = puVar11 + uVar1;
          *(uint **)((int)this + 8) = puVar11 + uVar10;
          return puVar2;
        }
        pvVar8 = pvVar7;
        if (((*(int *)((int)this + 8) - (int)pvVar7 & 0xfffffffcU) < 0x1000) ||
           (pvVar8 = *(void **)((int)pvVar7 + -4), (uint)((int)pvVar7 + (-4 - (int)pvVar8)) < 0x20))
        {
          FUN_1002e346(pvVar8);
          goto LAB_1001a94a;
        }
        goto LAB_1001a971;
      }
    }
LAB_1001a967:
    FUN_10001fb0();
  }
  FUN_10017fa0();
LAB_1001a971:
  FUN_10032f7f();
  pcVar5 = (code *)swi(3);
  puVar11 = (uint *)(*pcVar5)();
  return puVar11;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001a980 @ 1001a980
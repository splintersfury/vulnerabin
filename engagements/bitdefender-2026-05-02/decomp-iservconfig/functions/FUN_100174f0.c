undefined1 * __thiscall FUN_100174f0(void *this,uint *param_1,undefined1 *param_2)

{
  uint uVar1;
  int iVar2;
  uint *puVar3;
  code *pcVar4;
  int iVar5;
  void *pvVar6;
  void *pvVar7;
  undefined1 *puVar8;
  uint uVar9;
  uint uVar10;
  uint *puVar11;
  
                    /* WARNING: Load size is inaccurate */
  iVar2 = *this;
  iVar5 = *(int *)((int)this + 4) - iVar2;
  if (iVar5 != 0x7fffffff) {
    uVar1 = iVar5 + 1;
    uVar9 = *(int *)((int)this + 8) - iVar2;
    if (0x7fffffff - (uVar9 >> 1) < uVar9) {
      uVar10 = 0x7fffffff;
      uVar9 = 0x80000022;
LAB_1001753c:
      pvVar6 = operator_new(uVar9);
      if (pvVar6 != (void *)0x0) {
        puVar11 = (uint *)((int)pvVar6 + 0x23U & 0xffffffe0);
        puVar11[-1] = (uint)pvVar6;
        goto LAB_1001758a;
      }
    }
    else {
      uVar9 = (uVar9 >> 1) + uVar9;
      uVar10 = uVar1;
      if (uVar1 <= uVar9) {
        uVar10 = uVar9;
      }
      if (0xfff < uVar10) {
        uVar9 = uVar10 + 0x23;
        if (uVar9 <= uVar10) goto LAB_1001762a;
        goto LAB_1001753c;
      }
      if (uVar10 == 0) {
        puVar11 = (uint *)0x0;
      }
      else {
        puVar11 = (uint *)operator_new(uVar10);
      }
LAB_1001758a:
      puVar8 = (undefined1 *)(((int)param_1 - iVar2) + (int)puVar11);
      *puVar8 = *param_2;
                    /* WARNING: Load size is inaccurate */
      puVar3 = *this;
      if (param_1 == *(uint **)((int)this + 4)) {
        FUN_100301d0(puVar11,puVar3,(int)*(uint **)((int)this + 4) - (int)puVar3);
      }
      else {
        FUN_100301d0(puVar11,puVar3,(int)param_1 - (int)puVar3);
        FUN_100301d0((uint *)(puVar8 + 1),param_1,*(int *)((int)this + 4) - (int)param_1);
      }
                    /* WARNING: Load size is inaccurate */
      pvVar6 = *this;
      if (pvVar6 == (void *)0x0) {
LAB_10017604:
        *(uint **)this = puVar11;
        *(uint *)((int)this + 4) = uVar1 + (int)puVar11;
        *(uint *)((int)this + 8) = (int)puVar11 + uVar10;
        return puVar8;
      }
      pvVar7 = pvVar6;
      if (((uint)(*(int *)((int)this + 8) - (int)pvVar6) < 0x1000) ||
         (pvVar7 = *(void **)((int)pvVar6 + -4), (uint)((int)pvVar6 + (-4 - (int)pvVar7)) < 0x20)) {
        FUN_1002e346(pvVar7);
        goto LAB_10017604;
      }
    }
    FUN_10032f7f();
  }
  FUN_10017fa0();
LAB_1001762a:
  FUN_10001fb0();
  pcVar4 = (code *)swi(3);
  puVar8 = (undefined1 *)(*pcVar4)();
  return puVar8;
}


// FUNCTION_END

// FUNCTION_START: FUN_10017630 @ 10017630
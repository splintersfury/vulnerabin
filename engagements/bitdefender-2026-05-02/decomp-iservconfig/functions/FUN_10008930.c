uint * __thiscall
FUN_10008930(void *this,uint param_1,undefined4 param_2,int param_3,uint param_4,undefined2 param_5)

{
  int iVar1;
  uint *puVar2;
  code *pcVar3;
  uint *puVar4;
  uint uVar5;
  uint uVar6;
  uint *puVar7;
  uint uVar8;
  undefined4 *puVar9;
  
  iVar1 = *(int *)((int)this + 0x10);
  if (0x7ffffffeU - iVar1 < param_1) {
    FUN_10001eb0();
  }
  else {
    uVar6 = *(uint *)((int)this + 0x14);
    uVar8 = iVar1 + param_1 | 7;
    if (uVar8 < 0x7fffffff) {
      if (0x7ffffffe - (uVar6 >> 1) < uVar6) {
        uVar8 = 0x7ffffffe;
      }
      else {
        uVar5 = (uVar6 >> 1) + uVar6;
        if (uVar8 < uVar5) {
          uVar8 = uVar5;
        }
      }
    }
    else {
      uVar8 = 0x7ffffffe;
    }
    puVar4 = (uint *)FUN_10001e50(-(uint)(0xfffffffe < uVar8) | uVar8 + 1);
    *(uint *)((int)this + 0x14) = uVar8;
    *(uint *)((int)this + 0x10) = iVar1 + param_1;
    uVar8 = param_3 * 2;
    if (uVar6 < 8) {
      FUN_100301d0(puVar4,(uint *)this,uVar8);
      if (param_4 != 0) {
        puVar9 = (undefined4 *)(uVar8 + (int)puVar4);
        for (uVar6 = param_4 >> 1; uVar6 != 0; uVar6 = uVar6 - 1) {
          *puVar9 = CONCAT22(param_5,param_5);
          puVar9 = puVar9 + 1;
        }
        for (uVar6 = (uint)((param_4 & 1) != 0); uVar6 != 0; uVar6 = uVar6 - 1) {
          *(undefined2 *)puVar9 = param_5;
          puVar9 = (undefined4 *)((int)puVar9 + 2);
        }
      }
      FUN_100301d0((uint *)((int)puVar4 + (param_4 + param_3) * 2),(uint *)(param_3 * 2 + (int)this)
                   ,(iVar1 - param_3) * 2 + 2);
      *(uint **)this = puVar4;
      return (uint *)this;
    }
                    /* WARNING: Load size is inaccurate */
    puVar2 = *this;
    FUN_100301d0(puVar4,puVar2,uVar8);
    if (param_4 != 0) {
      puVar9 = (undefined4 *)(uVar8 + (int)puVar4);
      for (uVar5 = param_4 >> 1; uVar5 != 0; uVar5 = uVar5 - 1) {
        *puVar9 = CONCAT22(param_5,param_5);
        puVar9 = puVar9 + 1;
      }
      for (uVar8 = (uint)((param_4 & 1) != 0); uVar8 != 0; uVar8 = uVar8 - 1) {
        *(undefined2 *)puVar9 = param_5;
        puVar9 = (undefined4 *)((int)puVar9 + 2);
      }
    }
    FUN_100301d0((uint *)((int)puVar4 + (param_4 + param_3) * 2),(uint *)(param_3 * 2 + (int)puVar2)
                 ,(iVar1 - param_3) * 2 + 2);
    puVar7 = puVar2;
    if ((uVar6 * 2 + 2 < 0x1000) ||
       (puVar7 = (uint *)puVar2[-1], (uint)((int)puVar2 + (-4 - (int)puVar7)) < 0x20)) {
      FUN_1002e346(puVar7);
      *(uint **)this = puVar4;
      return (uint *)this;
    }
  }
  FUN_10032f7f();
  pcVar3 = (code *)swi(3);
  puVar4 = (uint *)(*pcVar3)();
  return puVar4;
}


// FUNCTION_END

// FUNCTION_START: FUN_10008ac0 @ 10008ac0
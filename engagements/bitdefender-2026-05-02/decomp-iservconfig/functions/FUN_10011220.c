void __thiscall FUN_10011220(void *this,undefined1 *param_1)

{
  char cVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  undefined1 *puVar5;
  uint *puVar6;
  undefined4 uVar7;
  int *piVar8;
  int *this_00;
  int *piVar9;
  undefined4 *puVar10;
  void *pvVar11;
  undefined1 *puVar12;
  uint uVar13;
  undefined1 local_25;
  undefined8 local_24;
  undefined1 local_15;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004ec65;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  *(undefined1 *)this = *param_1;
  *(undefined8 *)((int)this + 8) = 0;
                    /* WARNING: Load size is inaccurate */
  switch(*this) {
  case 1:
    piVar4 = *(int **)(param_1 + 8);
    this_00 = (int *)operator_new(8);
    local_8 = 0;
    *this_00 = 0;
    this_00[1] = 0;
    local_24 = CONCAT44(this_00,this_00);
    pvVar11 = operator_new(0x38);
    *(void **)pvVar11 = pvVar11;
    *(void **)((int)pvVar11 + 4) = pvVar11;
    *(void **)((int)pvVar11 + 8) = pvVar11;
    *(undefined2 *)((int)pvVar11 + 0xc) = 0x101;
    *this_00 = (int)pvVar11;
    local_8 = CONCAT31(local_8._1_3_,1);
    piVar9 = FUN_1001bdc0(this_00,*(undefined4 **)(*piVar4 + 4),(int)pvVar11,this);
    *(int **)(*this_00 + 4) = piVar9;
    piVar9 = (int *)*this_00;
    this_00[1] = piVar4[1];
    piVar4 = (int *)piVar9[1];
    if (*(char *)((int)piVar4 + 0xd) == '\0') {
      cVar1 = *(char *)(*piVar4 + 0xd);
      piVar8 = (int *)*piVar4;
      while (cVar1 == '\0') {
        cVar1 = *(char *)(*piVar8 + 0xd);
        piVar4 = piVar8;
        piVar8 = (int *)*piVar8;
      }
      *piVar9 = (int)piVar4;
      iVar2 = *(int *)(*this_00 + 4);
      iVar3 = *(int *)(iVar2 + 8);
      cVar1 = *(char *)(iVar3 + 0xd);
      while (cVar1 == '\0') {
        cVar1 = *(char *)(*(int *)(iVar3 + 8) + 0xd);
        iVar2 = iVar3;
        iVar3 = *(int *)(iVar3 + 8);
      }
      *(int *)(*this_00 + 8) = iVar2;
      *(int **)((int)this + 8) = this_00;
      *(undefined4 *)((int)this + 0xc) = local_24._4_4_;
    }
    else {
      *piVar9 = (int)piVar9;
      *(int *)(*this_00 + 8) = *this_00;
      *(int **)((int)this + 8) = this_00;
      *(undefined4 *)((int)this + 0xc) = local_24._4_4_;
    }
    break;
  case 2:
    piVar4 = *(int **)(param_1 + 8);
    local_24 = 0;
    puVar10 = (undefined4 *)operator_new(0xc);
    local_24 = CONCAT44(puVar10,&local_15);
    local_8 = 2;
    *puVar10 = 0;
    puVar10[1] = 0;
    puVar10[2] = 0;
    puVar5 = (undefined1 *)piVar4[1];
    puVar12 = (undefined1 *)*piVar4;
    if (puVar12 == puVar5) {
      *(undefined4 **)((int)this + 8) = puVar10;
      *(undefined4 **)((int)this + 0xc) = puVar10;
    }
    else {
      uVar13 = (int)puVar5 - (int)puVar12 >> 4;
      pvVar11 = FUN_1001ab40(uVar13);
      *puVar10 = pvVar11;
      puVar10[1] = pvVar11;
      puVar10[2] = (void *)(uVar13 * 0x10 + (int)pvVar11);
      local_8 = CONCAT31(local_8._1_3_,4);
      do {
        FUN_10011220(pvVar11,puVar12);
        pvVar11 = (void *)((int)pvVar11 + 0x10);
        puVar12 = puVar12 + 0x10;
      } while (puVar12 != puVar5);
      puVar10[1] = pvVar11;
      *(undefined4 **)((int)this + 8) = puVar10;
      *(undefined4 *)((int)this + 0xc) = local_24._4_4_;
    }
    break;
  case 3:
    puVar6 = *(uint **)(param_1 + 8);
    local_24 = 0;
    pvVar11 = operator_new(0x18);
    local_24 = CONCAT44(pvVar11,&local_25);
    local_8 = 5;
    FUN_100056d0(pvVar11,puVar6);
    *(void **)((int)this + 8) = pvVar11;
    *(undefined4 *)((int)this + 0xc) = local_24._4_4_;
    break;
  case 4:
    uVar7 = local_24._4_4_;
    local_24 = CONCAT71(local_24._1_7_,param_1[8]);
    *(undefined4 *)((int)this + 8) = (undefined4)local_24;
    *(undefined4 *)((int)this + 0xc) = uVar7;
    break;
  case 5:
  case 6:
    uVar7 = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)((int)this + 8) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)((int)this + 0xc) = uVar7;
    break;
  case 7:
    *(undefined8 *)((int)this + 8) = *(undefined8 *)(param_1 + 8);
  }
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100114b0 @ 100114b0
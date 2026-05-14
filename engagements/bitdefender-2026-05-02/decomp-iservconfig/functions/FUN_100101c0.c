undefined8 __thiscall FUN_100101c0(void *this,uint *param_1,uint param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  size_t sVar4;
  uint uVar5;
  uint uVar6;
  bool bVar7;
  longlong lVar8;
  uint *local_14;
  uint local_10;
  int local_c;
  
  local_14 = param_1;
  if ((param_3 < 1) && ((param_3 < 0 || (param_2 == 0)))) {
    return 0;
  }
  if (*(int *)((int)this + 0x38) == 0) {
    uVar5 = param_2;
    if (((uint *)**(undefined4 **)((int)this + 0x1c) != (uint *)0x0) &&
       (uVar1 = **(uint **)((int)this + 0x2c), uVar1 != 0)) {
      uVar6 = param_2;
      if (uVar1 < param_2) {
        uVar6 = uVar1;
      }
      FUN_100301d0(param_1,(uint *)**(undefined4 **)((int)this + 0x1c),uVar6);
      local_14 = (uint *)((int)param_1 + uVar6);
      uVar5 = param_2 - uVar6;
      **(int **)((int)this + 0x2c) = **(int **)((int)this + 0x2c) - uVar6;
      **(int **)((int)this + 0x1c) = **(int **)((int)this + 0x1c) + uVar6;
    }
    if (*(int *)((int)this + 0x4c) != 0) {
      if (**(int **)((int)this + 0xc) == (int)this + 0x3c) {
        iVar3 = *(int *)((int)this + 0x54);
        iVar2 = *(int *)((int)this + 0x50);
        **(int **)((int)this + 0xc) = iVar2;
        **(int **)((int)this + 0x1c) = iVar2;
        **(int **)((int)this + 0x2c) = iVar3 - iVar2;
      }
      while (0xfff < uVar5) {
        sVar4 = _fread(local_14,1,0xfff,*(FILE **)((int)this + 0x4c));
        uVar5 = uVar5 - sVar4;
        local_14 = (uint *)((int)local_14 + sVar4);
        if (sVar4 != 0xfff) {
          return CONCAT44(param_3 - (uint)(param_2 < uVar5),param_2 - uVar5);
        }
      }
      if (uVar5 != 0) {
        sVar4 = _fread(local_14,1,uVar5,*(FILE **)((int)this + 0x4c));
        uVar5 = uVar5 - sVar4;
      }
    }
    return CONCAT44(param_3 - (uint)(param_2 < uVar5),param_2 - uVar5);
  }
  local_10 = param_2;
  local_14 = (uint *)param_3;
  do {
    lVar8 = FUN_10005b40((int)this);
    if (lVar8 < 1) {
                    /* WARNING: Load size is inaccurate */
      iVar3 = (**(code **)(*this + 0x1c))();
      if (iVar3 == -1) {
LAB_1001029b:
        return CONCAT44((param_3 - (int)local_14) - (uint)(param_2 < local_10),param_2 - local_10);
      }
      uVar5 = 1;
      bVar7 = local_10 != 0;
      local_10 = local_10 - 1;
      *(char *)param_1 = (char)iVar3;
      local_14 = (uint *)((int)local_14 + -1 + (uint)bVar7);
    }
    else {
      if (CONCAT44(local_14,local_10) < lVar8) {
        lVar8 = CONCAT44(local_14,local_10);
      }
      local_c = (int)((ulonglong)lVar8 >> 0x20);
      uVar5 = (uint)lVar8;
      FUN_100301d0(param_1,(uint *)**(undefined4 **)((int)this + 0x1c),uVar5);
      bVar7 = local_10 < uVar5;
      local_10 = local_10 - uVar5;
      local_14 = (uint *)(((int)local_14 - local_c) - (uint)bVar7);
      **(int **)((int)this + 0x2c) = **(int **)((int)this + 0x2c) - uVar5;
      **(int **)((int)this + 0x1c) = **(int **)((int)this + 0x1c) + uVar5;
    }
    param_1 = (uint *)((int)param_1 + uVar5);
    if (((int)local_14 < 1) && (((int)local_14 < 0 || (local_10 == 0)))) goto LAB_1001029b;
  } while( true );
}


// FUNCTION_END

// FUNCTION_START: FUN_10010390 @ 10010390

/* WARNING: Type propagation algorithm not settling */
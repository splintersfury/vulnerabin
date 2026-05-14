undefined8 __thiscall FUN_10010020(void *this,uint *param_1,uint param_2,int param_3)

{
  int iVar1;
  size_t sVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  bool bVar6;
  longlong lVar7;
  uint *local_18;
  int local_14;
  
  if (*(int *)((int)this + 0x38) != 0) {
    local_18 = param_1;
    iVar3 = param_3;
    uVar5 = param_2;
    if ((-1 < param_3) && ((0 < param_3 || (param_2 != 0)))) {
      do {
        lVar7 = FUN_10005b20((int)this);
        if (lVar7 < 1) {
                    /* WARNING: Load size is inaccurate */
          iVar1 = (**(code **)(*this + 0xc))((char)*local_18);
          if (iVar1 == -1) break;
          bVar6 = uVar5 != 0;
          uVar5 = uVar5 - 1;
          uVar4 = 1;
          iVar3 = iVar3 + -1 + (uint)bVar6;
        }
        else {
          if (CONCAT44(iVar3,uVar5) < lVar7) {
            lVar7 = CONCAT44(iVar3,uVar5);
          }
          local_14 = (int)((ulonglong)lVar7 >> 0x20);
          uVar4 = (uint)lVar7;
          FUN_100301d0((uint *)**(undefined4 **)((int)this + 0x20),local_18,uVar4);
          bVar6 = uVar5 < uVar4;
          uVar5 = uVar5 - uVar4;
          iVar3 = (iVar3 - local_14) - (uint)bVar6;
          **(int **)((int)this + 0x30) = **(int **)((int)this + 0x30) - uVar4;
          **(int **)((int)this + 0x20) = **(int **)((int)this + 0x20) + uVar4;
        }
        local_18 = (uint *)((int)local_18 + uVar4);
        if ((iVar3 < 1) && ((iVar3 < 0 || (uVar5 == 0)))) break;
      } while( true );
    }
    return CONCAT44((param_3 - iVar3) - (uint)(param_2 < uVar5),param_2 - uVar5);
  }
  if ((uint *)**(undefined4 **)((int)this + 0x20) == (uint *)0x0) {
    uVar5 = 0;
  }
  else {
    uVar5 = **(uint **)((int)this + 0x30);
  }
  local_14 = (int)uVar5 >> 0x1f;
  uVar4 = param_2;
  iVar3 = param_3;
  if ((-1 < param_3) && ((0 < param_3 || (param_2 != 0)))) {
    if ((-1 < local_14) && (((int)uVar5 < 0 && -1 < local_14 || (uVar5 != 0)))) {
      if ((param_3 <= local_14) && ((param_3 < local_14 || (param_2 < uVar5)))) {
        local_14 = param_3;
        uVar5 = param_2;
      }
      FUN_100301d0((uint *)**(undefined4 **)((int)this + 0x20),param_1,uVar5);
      uVar4 = param_2 - uVar5;
      iVar3 = (param_3 - local_14) - (uint)(param_2 < uVar5);
      param_1 = (uint *)((int)param_1 + uVar5);
      **(int **)((int)this + 0x30) = **(int **)((int)this + 0x30) - uVar5;
      **(int **)((int)this + 0x20) = **(int **)((int)this + 0x20) + uVar5;
      if ((iVar3 < 0) || ((iVar3 < 1 && (uVar4 == 0)))) goto LAB_100101aa;
    }
    if (*(FILE **)((int)this + 0x4c) != (FILE *)0x0) {
      sVar2 = _fwrite(param_1,1,uVar4,*(FILE **)((int)this + 0x4c));
      bVar6 = uVar4 < sVar2;
      uVar4 = uVar4 - sVar2;
      iVar3 = iVar3 - (uint)bVar6;
    }
  }
LAB_100101aa:
  return CONCAT44((param_3 - iVar3) - (uint)(param_2 < uVar4),param_2 - uVar4);
}


// FUNCTION_END

// FUNCTION_START: FUN_100101c0 @ 100101c0

/* WARNING: Removing unreachable block (ram,0x10010219) */
/* WARNING: Removing unreachable block (ram,0x1001022b) */
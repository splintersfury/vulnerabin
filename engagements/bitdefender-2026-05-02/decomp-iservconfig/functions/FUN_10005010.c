undefined8 __thiscall FUN_10005010(void *this,uint *param_1,uint param_2,int param_3)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  bool bVar6;
  longlong lVar7;
  int local_14;
  
  uVar4 = param_2;
  iVar5 = param_3;
  if ((-1 < param_3) && ((0 < param_3 || (param_2 != 0)))) {
    do {
      lVar7 = FUN_10005b40((int)this);
      if (lVar7 < 1) {
                    /* WARNING: Load size is inaccurate */
        sVar1 = (**(code **)(*this + 0x1c))();
        if (sVar1 == -1) break;
        bVar6 = uVar4 != 0;
        uVar4 = uVar4 - 1;
        iVar5 = iVar5 + -1 + (uint)bVar6;
        *(short *)param_1 = sVar1;
        iVar2 = 2;
      }
      else {
        if (CONCAT44(iVar5,uVar4) < lVar7) {
          lVar7 = CONCAT44(iVar5,uVar4);
        }
        local_14 = (int)((ulonglong)lVar7 >> 0x20);
        uVar3 = (uint)lVar7;
        FUN_100301d0(param_1,(uint *)**(undefined4 **)((int)this + 0x1c),uVar3 * 2);
        iVar2 = uVar3 * 2;
        bVar6 = uVar4 < uVar3;
        uVar4 = uVar4 - uVar3;
        iVar5 = (iVar5 - local_14) - (uint)bVar6;
        **(int **)((int)this + 0x2c) = **(int **)((int)this + 0x2c) - uVar3;
        **(int **)((int)this + 0x1c) = **(int **)((int)this + 0x1c) + iVar2;
      }
      param_1 = (uint *)((int)param_1 + iVar2);
      if ((iVar5 < 1) && ((iVar5 < 0 || (uVar4 == 0)))) break;
    } while( true );
  }
  return CONCAT44((param_3 - iVar5) - (uint)(param_2 < uVar4),param_2 - uVar4);
}


// FUNCTION_END

// FUNCTION_START: FUN_10005100 @ 10005100
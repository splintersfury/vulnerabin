undefined8 __thiscall FUN_1000e850(void *this,uint *param_1,uint param_2,int param_3)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  bool bVar5;
  longlong lVar6;
  int local_14;
  
  iVar2 = param_3;
  uVar4 = param_2;
  if ((-1 < param_3) && ((0 < param_3 || (param_2 != 0)))) {
    do {
      lVar6 = FUN_10005b20((int)this);
      if (lVar6 < 1) {
                    /* WARNING: Load size is inaccurate */
        iVar1 = (**(code **)(*this + 0xc))((char)*param_1);
        if (iVar1 == -1) break;
        bVar5 = uVar4 != 0;
        uVar4 = uVar4 - 1;
        uVar3 = 1;
        iVar2 = iVar2 + -1 + (uint)bVar5;
      }
      else {
        if (CONCAT44(iVar2,uVar4) < lVar6) {
          lVar6 = CONCAT44(iVar2,uVar4);
        }
        local_14 = (int)((ulonglong)lVar6 >> 0x20);
        uVar3 = (uint)lVar6;
        FUN_100301d0((uint *)**(undefined4 **)((int)this + 0x20),param_1,uVar3);
        bVar5 = uVar4 < uVar3;
        uVar4 = uVar4 - uVar3;
        iVar2 = (iVar2 - local_14) - (uint)bVar5;
        **(int **)((int)this + 0x30) = **(int **)((int)this + 0x30) - uVar3;
        **(int **)((int)this + 0x20) = **(int **)((int)this + 0x20) + uVar3;
      }
      param_1 = (uint *)((int)param_1 + uVar3);
      if ((iVar2 < 1) && ((iVar2 < 0 || (uVar4 == 0)))) break;
    } while( true );
  }
  return CONCAT44((param_3 - iVar2) - (uint)(param_2 < uVar4),param_2 - uVar4);
}


// FUNCTION_END

// FUNCTION_START: FUN_1000e930 @ 1000e930

/* WARNING: Removing unreachable block (ram,0x1000e977) */
/* WARNING: Removing unreachable block (ram,0x1000e981) */
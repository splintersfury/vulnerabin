int * __fastcall FUN_1001c8f0(int *param_1,uint *param_2,uint *param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  longlong lVar7;
  longlong lVar8;
  longlong lVar9;
  
  uVar3 = *param_3;
  lVar7 = __allmul(param_3[1],0,*param_2,0);
  uVar1 = (uint)((ulonglong)lVar7 >> 0x20);
  lVar8 = __allmul(uVar3,0,param_2[1],0);
  uVar2 = (uint)((ulonglong)lVar8 >> 0x20);
  lVar9 = __allmul(uVar3,0,*param_2,0);
  uVar3 = (uint)((ulonglong)lVar9 >> 0x20);
  uVar4 = uVar3 + (uint)lVar8;
  lVar9 = __allmul(param_3[1],0,param_2[1],0);
  lVar9 = lVar9 + (ulonglong)
                  ((uint)CARRY4(uVar3,(uint)lVar8) + (uint)CARRY4(uVar4,(uint)lVar7) +
                  (uint)(0x7fffffff < uVar4 + (uint)lVar7));
  uVar5 = (uint)lVar9;
  uVar6 = uVar5 + uVar2;
  uVar3 = param_2[2];
  uVar4 = param_3[2];
  *param_1 = uVar6 + uVar1;
  param_1[1] = (int)((ulonglong)lVar9 >> 0x20) + (uint)CARRY4(uVar5,uVar2) +
               (uint)CARRY4(uVar6,uVar1);
  param_1[2] = uVar4 + 0x40 + uVar3;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001c9a0 @ 1001c9a0
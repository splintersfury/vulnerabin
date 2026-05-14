void __fastcall FUN_10010390(int param_1)

{
  undefined1 *puVar1;
  int iVar2;
  code *pcVar3;
  uint uVar4;
  int iVar5;
  uint *******pppppppuVar6;
  undefined1 uVar7;
  uint *******pppppppuVar8;
  uint uVar9;
  uint local_44;
  undefined1 *local_3c;
  int local_38;
  undefined4 local_34;
  uint *******local_30 [4];
  uint local_20;
  uint local_1c;
  undefined1 local_15;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004ea9d;
  local_10 = ExceptionList;
  uVar4 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  uVar9 = **(uint **)(param_1 + 0x1c);
  local_14 = uVar4;
  if (uVar9 != 0) {
    iVar5 = **(int **)(param_1 + 0x2c);
    if (uVar9 < iVar5 + uVar9) {
      **(int **)(param_1 + 0x2c) = iVar5 + -1;
      **(int **)(param_1 + 0x1c) = **(int **)(param_1 + 0x1c) + 1;
      goto LAB_100105d0;
    }
  }
  if (*(int *)(param_1 + 0x4c) != 0) {
    if (**(int **)(param_1 + 0xc) == param_1 + 0x3c) {
      iVar5 = *(int *)(param_1 + 0x54);
      iVar2 = *(int *)(param_1 + 0x50);
      **(int **)(param_1 + 0xc) = iVar2;
      **(int **)(param_1 + 0x1c) = iVar2;
      **(int **)(param_1 + 0x2c) = iVar5 - iVar2;
    }
    if (*(int *)(param_1 + 0x38) == 0) {
      _fgetc(*(FILE **)(param_1 + 0x4c));
    }
    else {
      local_20 = 0;
      local_1c = 0xf;
      local_30[0] = (uint *******)0x0;
      local_8 = 0;
      iVar5 = _fgetc(*(FILE **)(param_1 + 0x4c));
      if (iVar5 != -1) {
LAB_10010471:
        uVar9 = local_20;
        uVar7 = (undefined1)iVar5;
        local_34 = CONCAT31(local_34._1_3_,uVar7);
        if (local_20 < local_1c) {
          pppppppuVar6 = (uint *******)local_30;
          if (0xf < local_1c) {
            pppppppuVar6 = local_30[0];
          }
          puVar1 = (undefined1 *)((int)pppppppuVar6 + local_20);
          local_20 = local_20 + 1;
          *puVar1 = uVar7;
          *(undefined1 *)((int)pppppppuVar6 + uVar9 + 1) = 0;
        }
        else {
          local_44 = local_44 & 0xffffff00;
          FUN_10014ac0(local_30,local_20,local_44,uVar7);
        }
        pppppppuVar6 = (uint *******)local_30;
        if (0xf < local_1c) {
          pppppppuVar6 = local_30[0];
        }
        pppppppuVar8 = (uint *******)local_30;
        if (0xf < local_1c) {
          pppppppuVar8 = local_30[0];
        }
        iVar5 = (**(code **)(**(int **)(param_1 + 0x38) + 0x18))
                          (param_1 + 0x40,pppppppuVar8,(int)pppppppuVar6 + local_20,&local_38,
                           &local_15,&local_14,&local_3c,uVar4);
        if ((iVar5 == 0) || (iVar5 == 1)) {
          if (local_3c == &local_15) goto code_r0x10010500;
          pppppppuVar6 = (uint *******)local_30;
          if (0xf < local_1c) {
            pppppppuVar6 = local_30[0];
          }
          for (iVar5 = (local_20 - local_38) + (int)pppppppuVar6; 0 < iVar5; iVar5 = iVar5 + -1) {
            _ungetc((int)*(char *)(iVar5 + -1 + local_38),*(FILE **)(param_1 + 0x4c));
          }
        }
      }
LAB_1001054d:
      if (0xf < local_1c) {
        pppppppuVar6 = local_30[0];
        if ((0xfff < local_1c + 1) &&
           (pppppppuVar6 = (uint *******)local_30[0][-1],
           0x1f < (uint)((int)local_30[0] + (-4 - (int)pppppppuVar6)))) {
          FUN_10032f7f();
          pcVar3 = (code *)swi(3);
          (*pcVar3)();
          return;
        }
        FUN_1002e346(pppppppuVar6);
      }
    }
  }
LAB_100105d0:
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
code_r0x10010500:
  pppppppuVar6 = (uint *******)local_30;
  if (0xf < local_1c) {
    pppppppuVar6 = local_30[0];
  }
  uVar9 = local_38 - (int)pppppppuVar6;
  if (local_20 < (uint)(local_38 - (int)pppppppuVar6)) {
    uVar9 = local_20;
  }
  pppppppuVar6 = (uint *******)local_30;
  if (0xf < local_1c) {
    pppppppuVar6 = local_30[0];
  }
  local_20 = local_20 - uVar9;
  FUN_100301d0((uint *)pppppppuVar6,(uint *)((int)pppppppuVar6 + uVar9),local_20 + 1);
  iVar5 = _fgetc(*(FILE **)(param_1 + 0x4c));
  if (iVar5 == -1) goto LAB_1001054d;
  goto LAB_10010471;
}


// FUNCTION_END

// FUNCTION_START: underflow @ 10010600

/* Library Function - Single Match
    protected: virtual int __thiscall std::basic_filebuf<char,struct std::char_traits<char>
   >::underflow(void)
   
   Library: Visual Studio 2019 Release */

int __thiscall
std::basic_filebuf<char,struct_std::char_traits<char>_>::underflow
          (basic_filebuf<char,struct_std::char_traits<char>_> *this)

{
  byte *pbVar1;
  int iVar2;
  
  pbVar1 = (byte *)**(undefined4 **)(this + 0x1c);
  if ((pbVar1 != (byte *)0x0) && (pbVar1 < pbVar1 + **(int **)(this + 0x2c))) {
    return (uint)*pbVar1;
  }
  iVar2 = (**(code **)(*(int *)this + 0x1c))();
  if (iVar2 == -1) {
    return -1;
  }
  (**(code **)(*(int *)this + 0x10))(iVar2);
  return iVar2;
}


// FUNCTION_END

// FUNCTION_START: pbackfail @ 10010640

/* Library Function - Single Match
    protected: virtual int __thiscall std::basic_filebuf<char,struct std::char_traits<char>
   >::pbackfail(int)
   
   Library: Visual Studio 2019 Release */

int __thiscall
std::basic_filebuf<char,struct_std::char_traits<char>_>::pbackfail
          (basic_filebuf<char,struct_std::char_traits<char>_> *this,int param_1)

{
  basic_filebuf<char,struct_std::char_traits<char>_> *pbVar1;
  uint uVar2;
  basic_filebuf<char,struct_std::char_traits<char>_> *pbVar3;
  int iVar4;
  
  uVar2 = **(uint **)(this + 0x1c);
  if (((uVar2 != 0) && (**(uint **)(this + 0xc) < uVar2)) &&
     ((param_1 == -1 || ((uint)*(byte *)(uVar2 - 1) == param_1)))) {
    **(int **)(this + 0x2c) = **(int **)(this + 0x2c) + 1;
    **(int **)(this + 0x1c) = **(int **)(this + 0x1c) + -1;
    if (param_1 == -1) {
      param_1 = 0;
    }
    return param_1;
  }
  if ((*(FILE **)(this + 0x4c) != (FILE *)0x0) && (param_1 != -1)) {
    if ((*(int *)(this + 0x38) == 0) &&
       (iVar4 = _ungetc(param_1 & 0xff,*(FILE **)(this + 0x4c)), iVar4 != -1)) {
      return param_1;
    }
    pbVar1 = this + 0x3c;
    if ((basic_filebuf<char,struct_std::char_traits<char>_> *)**(int **)(this + 0x1c) != pbVar1) {
      *pbVar1 = SUB41(param_1,0);
      pbVar3 = (basic_filebuf<char,struct_std::char_traits<char>_> *)**(int **)(this + 0xc);
      if (pbVar3 != pbVar1) {
        *(basic_filebuf<char,struct_std::char_traits<char>_> **)(this + 0x50) = pbVar3;
        *(int *)(this + 0x54) = **(int **)(this + 0x2c) + **(int **)(this + 0x1c);
      }
      **(int **)(this + 0xc) = (int)pbVar1;
      **(int **)(this + 0x1c) = (int)pbVar1;
      **(undefined4 **)(this + 0x2c) = 1;
      return param_1;
    }
  }
  return -1;
}


// FUNCTION_END

// FUNCTION_START: FUN_100106f0 @ 100106f0
undefined1 FUN_10011900(void)

{
  return 1;
}


// FUNCTION_END

// FUNCTION_START: _Initcvt @ 10011910

/* Library Function - Single Match
    protected: void __thiscall std::basic_filebuf<char,struct std::char_traits<char>
   >::_Initcvt(class std::codecvt<char,char,struct _Mbstatet> const &)
   
   Library: Visual Studio 2019 Release */

void __thiscall
std::basic_filebuf<char,struct_std::char_traits<char>_>::_Initcvt
          (basic_filebuf<char,struct_std::char_traits<char>_> *this,
          codecvt<char,char,struct__Mbstatet> *param_1)

{
  char cVar1;
  
  cVar1 = (**(code **)(*(int *)param_1 + 0xc))();
  if (cVar1 != '\0') {
    *(undefined4 *)(this + 0x38) = 0;
    return;
  }
  *(codecvt<char,char,struct__Mbstatet> **)(this + 0x38) = param_1;
  *(basic_filebuf<char,struct_std::char_traits<char>_> **)(this + 0xc) = this + 4;
  *(basic_filebuf<char,struct_std::char_traits<char>_> **)(this + 0x10) = this + 8;
  *(basic_filebuf<char,struct_std::char_traits<char>_> **)(this + 0x1c) = this + 0x14;
  *(basic_filebuf<char,struct_std::char_traits<char>_> **)(this + 0x20) = this + 0x18;
  *(basic_filebuf<char,struct_std::char_traits<char>_> **)(this + 0x2c) = this + 0x24;
  *(basic_filebuf<char,struct_std::char_traits<char>_> **)(this + 0x30) = this + 0x28;
  *(undefined4 *)(this + 8) = 0;
  *(undefined4 *)(this + 0x18) = 0;
  *(undefined4 *)(this + 0x28) = 0;
  *(undefined4 *)(this + 4) = 0;
  *(undefined4 *)(this + 0x14) = 0;
  *(undefined4 *)(this + 0x24) = 0;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100119a0 @ 100119a0
#pragma pack(1)
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <chrono>
#include <thread>
using namespace std;
class glob_vars{
public:
string name;
string name_store;
long long file_size;
uint64_t  pe_start;
char archi;
int nos;
int sofoh;
char prog_ver;
int text_size_sec;
int sofid;
int sofuid;
int aep;
int bofc;
int bofd;
uint64_t ib;
uint64_t oh_start;
uint64_t sa;
uint64_t fa;
uint16_t mjosv;
uint16_t mnosv;
uint64_t sofi;
uint64_t sofh;
uint64_t subsys;
uint64_t dllchar;
uint64_t sofsr;
uint64_t nofras;
uint64_t sectbl32;
uint64_t sectbl64;
uint32_t name_rva;
uint32_t expt;
uint32_t impt;
uint32_t rest;
uint32_t exct;
uint32_t cert;
uint32_t brt;
uint32_t debt;
uint32_t archi2;
uint32_t globptr;
uint32_t tlas;
uint32_t lct;
uint32_t boui;
uint32_t iat;
uint32_t did;
uint32_t clrrh;
uint32_t reserved;
uint32_t expts;
uint32_t impts;
uint32_t rests;
uint32_t excts;
uint32_t certs;
uint32_t brts;
uint32_t debts;
uint32_t archis2;
uint32_t globptrs;
uint32_t tlass;
uint32_t lcts;
uint32_t bouis;
uint32_t iats;
uint32_t dids;
uint32_t clrrhs;
uint32_t reserveds;
uint32_t* ddarr[16]={&expt,&impt,&rest,&exct,&cert,&brt,&debt,&archi2,&globptr,&tlas,&lct,&boui,&iat,&did,&clrrh,&reserved};
uint32_t* ddarrs[16]={&expts,&impts,&rests,&excts,&certs,&brts,&debts,&archis2,&globptrs,&tlass,&lcts,&bouis,&iats,&dids,&clrrhs,&reserveds};
uint32_t* ddarr_size[16];
void reading(){
uint16_t lb=0x1234;
char* lbptr=(char*)&lb;
if(*lbptr==0x12){
cout<<"Not designed for Big Endian ";	
exit(1);
}			
cin>>name;
name_store=name;
if(name.size()<=4){cout<<"\nunable to open file";
exit(1);
}
name.erase(0,name.size()-4);
transform(name.begin(),name.end(),name.begin(),::tolower);
ifstream file(name_store,ios::binary);
if(name!=".exe"){
vector<uint8_t> mistake(2);
char* omistake=(char*)mistake.data();
if(file.is_open()==0){
cout<<"\nunable to convert";	
exit(1);
}
file.seekg(0,ios::beg);
file.read(omistake,2);
if(omistake[0]=='M'&&omistake[1]=='Z'){cout<<"\nThis file has not an exe extension but it might be an exe file want continue?\n";}
else{cout<<"\nunable to convert";
exit(1);
}
char choose;
cin>>choose;
if(choose!='y'&&choose!='Y'){
cout<<"\nExiting Process";
this_thread::sleep_for(chrono::seconds(1));
file.close();
exit(1);
}
}
file.seekg(0,ios::end);
file_size=file.tellg();
if(file_size==-1){cout<<"\nunable to convert";}
else if(file_size==0){
cout<<"\nunable to convert";	
exit(1);
}
vector<uint8_t> buffer(4);
vector<uint8_t> buffer_64(8);
vector<uint8_t> buffer_2 (2);
char* obuffer=(char*)buffer.data();
char* obuffer_64=(char*)buffer_64.data();
char* obuffer_2=(char*)buffer_2.data();
file.seekg(0,ios::beg);
file.read(obuffer,4);
if(buffer[0]!='M'||buffer[1]!='Z'){cout<<"\nunable to convert";
exit(1);
}
file.seekg(0x3c,ios::beg);
file.read(obuffer,4);
pe_start=*(uint32_t*)obuffer;
file.seekg(pe_start,ios::beg);
file.read(obuffer,4);
if(buffer[0]!='P'||buffer[1]!='E'||buffer[2]!='\0'||buffer[3]!='\0'){
cout<<"\nunable to convert";
exit(1);
}
file.seekg(pe_start+4,ios::beg);
file.read(obuffer,2);
uint16_t cpuarch=*(uint16_t*)obuffer;
if(cpuarch==0x014c){
archi=32;	
}
else if(cpuarch==0x8664){
archi=64;	
}
else{cout<<"\nunable to convert ";
exit(1);
}
file.read(obuffer,2);
nos=*(uint16_t*)obuffer;	
file.seekg(20+pe_start,ios::beg);
file.read(obuffer,2);
sofoh=*(uint16_t*)obuffer;
oh_start=pe_start+24;
file.seekg(oh_start,ios::beg);
file.read(obuffer,2);
uint16_t opth=*(uint16_t*)obuffer; 
if(opth==0x10b){
prog_ver=32;
}
else{
prog_ver=64;
}  
file.seekg(4+oh_start,ios::beg);
file.read(obuffer,4);
text_size_sec=*(uint32_t*)obuffer;
file.seekg(8+oh_start,ios::beg);
file.read(obuffer,4);
sofid=*(uint32_t*)obuffer;
file.seekg(12+oh_start,ios::beg);
file.read(obuffer,4);
sofuid=*(uint32_t*)obuffer;
file.seekg(16+oh_start,ios::beg);
file.read(obuffer,4);
aep=*(uint32_t*)obuffer;
file.seekg(20+oh_start,ios::beg);
file.read(obuffer,4);
bofc=*(uint32_t*)obuffer;
if(prog_ver==32){
file.seekg(24+oh_start,ios::beg);
file.read(obuffer,4);
bofd=*(uint32_t*)obuffer;}
if(prog_ver==64){
file.seekg(24+oh_start,ios::beg);
file.read(obuffer_64,8);
ib=*(uint64_t*)obuffer_64;
}
else{
file.seekg(28+oh_start,ios::beg);
file.read(obuffer,4);
ib=*(uint32_t*)obuffer;	
}
if(prog_ver==64){
file.seekg(36+oh_start,ios::beg);	
file.read(obuffer,4);
sa=*(uint32_t*)obuffer;
}
else{
file.seekg(32+oh_start,ios::beg);
file.read(obuffer,4);
sa=*(uint32_t*)obuffer;	
}
if(prog_ver==64){
file.seekg(40+oh_start,ios::beg);	
file.read(obuffer,4);
fa=*(uint32_t*)obuffer;
}
else{
file.seekg(36+oh_start,ios::beg);
file.read(obuffer,4);
fa=*(uint32_t*)obuffer;		
}
if(prog_ver==64){
file.seekg(44+oh_start,ios::beg);	
file.read(obuffer_2,2);
mjosv=*(uint16_t*)obuffer_2;
}
else{
file.seekg(40+oh_start,ios::beg);
file.read(obuffer_2,2);
mjosv=*(uint16_t*)obuffer_2;	
}
if(prog_ver==64){
file.seekg(46+oh_start,ios::beg);	
file.read(obuffer_2,2);
mnosv=*(uint16_t*)obuffer_2;
}
else{
file.seekg(42+oh_start,ios::beg);
file.read(obuffer_2,2);
mnosv=*(uint16_t*)obuffer_2;	
}
if(prog_ver==64){
file.seekg(60+oh_start,ios::beg);	
file.read(obuffer,4);
sofi=*(uint32_t*)obuffer;
}
else{
file.seekg(56+oh_start,ios::beg);
file.read(obuffer,4);
sofi=*(uint32_t*)obuffer;	
}
if(prog_ver==64){
file.seekg(64+oh_start,ios::beg);	
file.read(obuffer,4);
sofh=*(uint32_t*)obuffer;
}
else{
file.seekg(60+oh_start,ios::beg);
file.read(obuffer,4);
sofh=*(uint32_t*)obuffer;	
}
if(prog_ver==64){
file.seekg(72+oh_start,ios::beg);	
file.read(obuffer_2,2);
subsys=*(uint16_t*)obuffer_2;
}
else{
file.seekg(68+oh_start,ios::beg);
file.read(obuffer_2,2);
subsys=*(uint16_t*)obuffer_2;	
}
if(prog_ver==64){
file.seekg(74+oh_start,ios::beg);	
file.read(obuffer_2,2);
dllchar=*(uint16_t*)obuffer_2;
}
else{
file.seekg(70+oh_start,ios::beg);
file.read(obuffer_2,2);
dllchar=*(uint16_t*)obuffer_2;	
}
if(prog_ver==64){
file.seekg(80+oh_start,ios::beg);	
file.read(obuffer_64,8);
sofsr=*(uint64_t*)obuffer_64;
}
else{
file.seekg(72+oh_start,ios::beg);
file.read(obuffer,4);
sofsr=*(uint32_t*)obuffer;	
}
if(prog_ver==64){
file.seekg(108+oh_start,ios::beg);	
file.read(obuffer,4);
nofras=*(uint32_t*)obuffer;
}
else{
file.seekg(92+oh_start,ios::beg);
file.read(obuffer,4);
nofras=*(uint32_t*)obuffer;	
}
int dd32=oh_start+96;
int dd64=oh_start+112;
int off_ind=0;
int element=0;
int element2=0;
while(element2<16){
if(prog_ver==64){
file.seekg(dd64+off_ind,ios::beg);
file.read(obuffer,4);
*(ddarr[element])=*(uint32_t*)obuffer;
off_ind+=4;
element++;
file.seekg(dd64+off_ind,ios::beg);
file.read(obuffer,4);
*(ddarrs[element2])=*(uint32_t*)obuffer;
off_ind+=4;
element2++;
}
else{
file.seekg(dd32+off_ind,ios::beg);
file.read(obuffer,4);
*(ddarr[element])=*(uint32_t*)obuffer;
off_ind+=4;
element++;
file.seekg(dd32+off_ind,ios::beg);
file.read(obuffer,4);
*(ddarrs[element2])=*(uint32_t*)obuffer;
off_ind+=4;
element2++;
}
};
file.seekg(12+dd32,ios::beg);
file.read(obuffer,4);
name_rva=*(uint32_t*)obuffer;

}

};


    
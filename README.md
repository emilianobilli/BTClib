# BTClib
Python Bitcoin Library

## btckeys

### from_integer()
```
pk = btckeys.from_integer(1)
print pk.to_wif()  -> 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf
print pk.to_addr() -> 1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm
```
### from_paraphrase()
sha256(paraphrase)
```
pk = btckeys.from_paraphrase('SatoshiNakamoto')
print pk.to_wif()   -> 5J43rJ8JFyu57TrtRz1iEAVhXngxf29x47ibFsadZvNpfZYuDPG
print pk.to_addr()  -> 1LDtV9NiqDJESjNDEdGBUhWdVutvpLAZXA
```
### from_wif()
```
pk = btckeys.from_wif('5J43rJ8JFyu57TrtRz1iEAVhXngxf29x47ibFsadZvNpfZYuDPG')
print pk.to_wif()   -> 5J43rJ8JFyu57TrtRz1iEAVhXngxf29x47ibFsadZvNpfZYuDPG
print pk.to_addr()  -> 1LDtV9NiqDJESjNDEdGBUhWdVutvpLAZXA
```

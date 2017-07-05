# BTClib
Python Bitcoin Library

## btckeys

### from_integer()
```
pk = btckeys.from_integer(1)
pk.to_wif()
pk.to_addr()
```
### from_paraphrase()
sha256(paraphrase)
```
pk = btckeys.from_paraphrase('SatoshiNakamoto')
pk.to_wif()
pk.to_addr()
```

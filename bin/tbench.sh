
#usage:
#tbench-script SIZE NUM_MESSAGES ITERATIONS RECIEVER OUTPUT_FILE
s=$1
n=$2
i=$3
r=$4
outfile=$5

S=0
X=1

for (( t=0; t<3000 ; t=t+50)) ; 
do

for (( sloop=0, S=0; sloop<101 ; sloop=sloop+10, S=S+10)) ; 
do

for (( xloop=0, X=1; xloop<8 ; xloop=xloop+1, X=2**xloop)) ; 
do

for (( repeat=0; repeat<5 ; repeat=repeat+1 )) ; 
do

echo "#gnunet-tbench -c gnunet.conf -s $s -n $n -i $i -t $t -S $S -X $X   -r $r -- repeat = $repeat"
echo "#gnunet-tbench -c gnunet.conf -s $s -n $n -i $i -t $t -S $S -X $X   -r $r -- repeat = $repeat" >> $outfile	
       gnunet-tbench -c gnunet.conf -s $s -n $n -i $i -t $t -S $S -X $X   -r $r	 >> $outfile

done

done

done

done

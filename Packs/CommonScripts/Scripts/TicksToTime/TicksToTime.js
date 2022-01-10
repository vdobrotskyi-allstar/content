//get date in string
var getDateString = function(obj) {
    var month = "0" + obj.Month;
    var day = "0" + obj.Day;
    var hours = "0" + obj.Hours;
    var minutes = "0" + obj.Minutes;
    var seconds = "0" + obj.Seconds;
    var strTime = obj.Year+'-'+month.substr(-2)+'-'+day.substr(-2) + ' '+hours.substr(-2) +':'+ minutes.substr(-2) +':'+ seconds.substr(-2);
    return strTime;
}

//ticks are in nanotime; convert to millis
var ticksToMillis = args.ticks / 10000;
//ticks are recorded from 1/1/1601. this is mili diff
var epocDiff = -11644473600000;
//create date object with the tick time
var tickDate = new Date(Math.round(ticksToMillis + epocDiff));

var obj = {
    Epoc: tickDate.getTime(),
    UTC: {
        Year: tickDate.getUTCFullYear(),
        Month: tickDate.getUTCMonth()+1,
        Day: tickDate.getUTCDate(),
        Hours: tickDate.getUTCHours(),
        Minutes: tickDate.getUTCMinutes(),
        Seconds: tickDate.getUTCSeconds()
    },
    Local: {
        Year: tickDate.getFullYear(),
        Month: tickDate.getMonth()+1,
        Day: tickDate.getDate(),
        Hours: tickDate.getHours(),
        Minutes: tickDate.getMinutes(),
        Seconds: tickDate.getSeconds()
    }
};
obj.UTC.Display = getDateString(obj.UTC);
obj.Local.Display = getDateString(obj.Local);

return({'HumanReadable': obj.Local.Display,'ContentsFormat': formats.json, 'Type': entryTypes['note'], 'Contents': obj});
